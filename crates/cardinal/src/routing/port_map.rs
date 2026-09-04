use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use k8s_common::PortRange;
use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::cache::ResourceKey;

use super::port_finder::PortFinderFactory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Port {
    Tcp(u16),
    Udp(u16),
}

impl Port {
    pub fn number(&self) -> u16 {
        match *self {
            Port::Tcp(p) | Port::Udp(p) => p,
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Port::Tcp(_))
    }

    pub fn is_udp(&self) -> bool {
        matches!(self, Port::Udp(_))
    }

    pub fn protocol_str(&self) -> &'static str {
        match self {
            Port::Tcp(_) => "TCP",
            Port::Udp(_) => "UDP",
        }
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Port::Tcp(p) => write!(f, "{p}/tcp"),
            Port::Udp(p) => write!(f, "{p}/udp"),
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PortError {
    #[error("port {0} is outside reserved range")]
    OutOfRange(Port),
    #[error("port {0} is already occupied by route '{1}'")]
    Occupied(Port, ResourceKey),
    #[error("auto port pool is exhausted")]
    Exhausted,
}

/// Status of candidate port search holding an acquired per-port mutex guard.
#[derive(Debug)]
pub enum PortCandidate {
    /// Port is already bound and owned by this resource key.
    Bound(Port, OwnedMutexGuard<()>),
    /// Port is available and locked, but not yet committed/bound.
    Available(Port, OwnedMutexGuard<()>),
}

impl PortCandidate {
    /// Returns the port enum regardless of whether it is bound or available.
    pub fn port(&self) -> Port {
        match *self {
            PortCandidate::Bound(p, _) | PortCandidate::Available(p, _) => p,
        }
    }

    /// Returns the port number regardless of whether it is bound or available.
    pub fn port_number(&self) -> u16 {
        self.port().number()
    }

    /// Returns true if the port was already bound to this resource key.
    pub fn is_bound(&self) -> bool {
        matches!(self, PortCandidate::Bound(..))
    }
}

struct Inner {
    bindings: BTreeMap<Port, ResourceKey>,
}

impl Inner {
    fn bind(&mut self, port: Port, key: ResourceKey) {
        // Clear any previous port allocated to this key
        self.bindings.retain(|&p, owner| p == port || *owner != key);
        self.bindings.insert(port, key);
    }

    fn unbind(&mut self, port: Port) -> Option<ResourceKey> {
        self.bindings.remove(&port)
    }

    fn unbind_key(&mut self, port: Port, expected_key: &ResourceKey) -> Option<ResourceKey> {
        if self.bindings.get(&port) == Some(expected_key) {
            self.bindings.remove(&port)
        } else {
            None
        }
    }

    fn clear(&mut self) {
        self.bindings.clear();
    }

    fn clear_namespace(&mut self, ns: &str) {
        self.bindings.retain(|_, owner| owner.namespace != ns);
    }
}

/// In-memory port mapping cache providing candidate lookup via LCG permutations
/// and per-port mutexes with non-blocking acquisition to prevent waiting on in-flight ports.
pub struct PortMap {
    range_reserved: Vec<PortRange>,
    range_auto: Vec<PortRange>,
    finder: PortFinderFactory,
    inner: RwLock<Inner>,
    locks: RwLock<HashMap<Port, Arc<AsyncMutex<()>>>>,
}

impl PortMap {
    pub fn new(
        range_reserved: impl IntoIterator<Item = PortRange>,
        range_auto: impl IntoIterator<Item = PortRange>,
    ) -> Self {
        let reserved: Vec<PortRange> = range_reserved.into_iter().collect();
        let auto: Vec<PortRange> = range_auto.into_iter().collect();
        let finder = PortFinderFactory::new(&auto);

        Self {
            range_reserved: reserved,
            range_auto: auto,
            finder,
            inner: RwLock::new(Inner {
                bindings: BTreeMap::new(),
            }),
            locks: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if a port number is within any reserved range without acquiring a lock.
    pub fn is_reserved_port(&self, port: u16) -> bool {
        self.range_reserved.iter().any(|r| r.contains(port))
    }

    /// Returns the reserved port ranges.
    pub fn range_reserved(&self) -> &[PortRange] {
        &self.range_reserved
    }

    /// Returns the auto port ranges.
    pub fn range_auto(&self) -> &[PortRange] {
        &self.range_auto
    }

    /// Returns or lazily creates a per-port mutex.
    fn get_or_create_port_lock(&self, port: Port) -> Arc<AsyncMutex<()>> {
        if let Some(lock) = self.locks.read().get(&port) {
            return lock.clone();
        }
        let mut locks = self.locks.write();
        locks
            .entry(port)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Attempts to lock a per-port mutex non-blockingly.
    fn try_lock_port(&self, port: Port) -> Option<OwnedMutexGuard<()>> {
        let lock = self.get_or_create_port_lock(port);
        lock.try_lock_owned().ok()
    }

    /// Finds candidate ports and returns them wrapped in per-port mutex guards.
    /// Auto ports try locks non-blockingly, advancing to next permutation candidates immediately.
    pub async fn find_free_ports(
        &self,
        requests: &[(ResourceKey, Port)],
    ) -> Result<Vec<PortCandidate>, PortError> {
        let mut candidates = Vec::with_capacity(requests.len());
        let mut batch_reserved = HashSet::new();

        for (key, requested_port) in requests {
            let port_num = requested_port.number();
            let is_udp = requested_port.is_udp();

            // Fixed port request
            if port_num != 0 {
                let port = *requested_port;
                if !self.is_reserved_port(port_num) {
                    return Err(PortError::OutOfRange(port));
                }

                if batch_reserved.contains(&port) {
                    return Err(PortError::Occupied(
                        port,
                        ResourceKey::new("unknown", "batch_conflict", ""),
                    ));
                }

                let is_bound = {
                    let inner = self.inner.read();
                    if let Some(owner) = inner.bindings.get(&port) {
                        if owner != key {
                            return Err(PortError::Occupied(port, owner.clone()));
                        }
                        true
                    } else {
                        false
                    }
                };

                let guard = self.try_lock_port(port).ok_or_else(|| {
                    PortError::Occupied(port, ResourceKey::new("unknown", "in_flight", ""))
                })?;

                batch_reserved.insert(port);
                if is_bound {
                    candidates.push(PortCandidate::Bound(port, guard));
                } else {
                    candidates.push(PortCandidate::Available(port, guard));
                }
                continue;
            }

            // Auto port with existing binding
            let existing_port = {
                let inner = self.inner.read();
                inner.bindings.iter().find_map(|(&port, owner)| {
                    if *owner == *key
                        && port.is_udp() == is_udp
                        && self.range_auto.iter().any(|r| r.contains(port.number()))
                        && !batch_reserved.contains(&port)
                    {
                        Some(port)
                    } else {
                        None
                    }
                })
            };

            if let Some(port) = existing_port
                && let Some(guard) = self.try_lock_port(port)
            {
                batch_reserved.insert(port);
                candidates.push(PortCandidate::Bound(port, guard));
                continue;
            }

            // New auto port allocation via LCG candidate cycle
            let cycle = self.finder.random_cycle();
            let mut allocated = None;

            for candidate_num in cycle {
                let candidate = if is_udp {
                    Port::Udp(candidate_num)
                } else {
                    Port::Tcp(candidate_num)
                };

                let is_free = {
                    let inner = self.inner.read();
                    !inner.bindings.contains_key(&candidate) && !batch_reserved.contains(&candidate)
                };

                if is_free && let Some(guard) = self.try_lock_port(candidate) {
                    batch_reserved.insert(candidate);
                    allocated = Some(PortCandidate::Available(candidate, guard));
                    break;
                }
            }

            match allocated {
                Some(c) => candidates.push(c),
                None => return Err(PortError::Exhausted),
            }
        }

        Ok(candidates)
    }

    /// Updates mapping with an observed or committed port binding.
    pub fn bind(&self, port: Port, key: ResourceKey) {
        self.inner.write().bind(port, key);
    }

    /// Removes binding for a given port.
    pub fn unbind(&self, port: Port) -> Option<ResourceKey> {
        self.inner.write().unbind(port)
    }

    /// Removes binding for a given port only if it is owned by `expected_key`.
    pub fn unbind_key(&self, port: Port, expected_key: &ResourceKey) -> Option<ResourceKey> {
        self.inner.write().unbind_key(port, expected_key)
    }

    /// Gets resource key owning a port if present.
    pub fn get_key(&self, port: Port) -> Option<ResourceKey> {
        self.inner.read().bindings.get(&port).cloned()
    }

    /// Gets port allocated to a resource key if present.
    pub fn get_port(&self, key: &ResourceKey) -> Option<Port> {
        self.inner
            .read()
            .bindings
            .iter()
            .find_map(|(port, owner)| if owner == key { Some(*port) } else { None })
    }

    /// Clears all active mappings.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Clears all active mappings belonging to a specific namespace.
    pub fn clear_namespace(&self, ns: &str) {
        self.inner.write().clear_namespace(ns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(resource: &str) -> ResourceKey {
        ResourceKey::new("default", "chal-1", resource)
    }

    fn make_map() -> PortMap {
        PortMap::new(
            vec![PortRange(20000..=20010)],
            vec![PortRange(30000..=30010)],
        )
    }

    async fn find_one(
        map: &PortMap,
        key: &ResourceKey,
        port: Port,
    ) -> Result<PortCandidate, PortError> {
        map.find_free_ports(&[(key.clone(), port)])
            .await
            .map(|mut v| v.pop().unwrap())
    }

    #[tokio::test]
    async fn test_find_fixed_port_within_range() {
        let map = make_map();
        let candidate = find_one(&map, &k("web"), Port::Tcp(20001)).await.unwrap();
        assert_eq!(candidate.port(), Port::Tcp(20001));
        assert!(!candidate.is_bound());

        // Binding marks it as occupied
        map.bind(Port::Tcp(20001), k("web"));
        assert_eq!(map.get_key(Port::Tcp(20001)), Some(k("web")));
        drop(candidate);

        // Same key finding same port returns Bound
        let bound = find_one(&map, &k("web"), Port::Tcp(20001)).await.unwrap();
        assert_eq!(bound.port(), Port::Tcp(20001));
        assert!(bound.is_bound());
        drop(bound);

        // Different key finding occupied port fails
        assert_eq!(
            find_one(&map, &k("pwn"), Port::Tcp(20001))
                .await
                .map(|c| c.port()),
            Err(PortError::Occupied(Port::Tcp(20001), k("web")))
        );
    }

    #[tokio::test]
    async fn test_find_fixed_port_multiple_ranges() {
        let map = PortMap::new(
            vec![
                PortRange(1000..=1010),
                PortRange(20000..=20010),
                PortRange(8080..=8080),
            ],
            vec![PortRange(30000..=30010)],
        );

        assert!(map.is_reserved_port(1005));
        assert!(map.is_reserved_port(20005));
        assert!(map.is_reserved_port(8080));
        assert!(!map.is_reserved_port(9000));

        let c1 = find_one(&map, &k("svc1"), Port::Tcp(1005)).await.unwrap();
        assert_eq!(c1.port(), Port::Tcp(1005));

        let c2 = find_one(&map, &k("svc2"), Port::Udp(8080)).await.unwrap();
        assert_eq!(c2.port(), Port::Udp(8080));
    }

    #[tokio::test]
    async fn test_find_fixed_port_out_of_range() {
        let map = make_map();
        assert_eq!(
            find_one(&map, &k("web"), Port::Tcp(8080))
                .await
                .map(|c| c.port()),
            Err(PortError::OutOfRange(Port::Tcp(8080)))
        );
    }

    #[tokio::test]
    async fn test_find_auto_port_lcg_selection() {
        let map = make_map();
        let c1 = find_one(&map, &k("pwn"), Port::Tcp(0)).await.unwrap();
        let p1 = c1.port();
        assert!((30000..=30010).contains(&p1.number()));
        assert!(p1.is_tcp());

        map.bind(p1, k("pwn"));
        drop(c1);

        // Idempotency: same key gets same port as Bound
        let bound = find_one(&map, &k("pwn"), Port::Tcp(0)).await.unwrap();
        assert_eq!(bound.port(), p1);
        assert!(bound.is_bound());
        drop(bound);

        // Next key gets a different free port as Available
        let c2 = find_one(&map, &k("web"), Port::Tcp(0)).await.unwrap();
        let p2 = c2.port();
        assert!((30000..=30010).contains(&p2.number()));
        assert_ne!(p1, p2);
    }

    #[tokio::test]
    async fn test_find_auto_port_multiple_ranges() {
        let map = PortMap::new(
            vec![PortRange(1000..=1010)],
            vec![PortRange(30000..=30002), PortRange(40000..=40002)],
        );

        let mut allocated = Vec::new();
        for i in 0..6 {
            let key = k(&format!("task-{i}"));
            let cand = find_one(&map, &key, Port::Tcp(0)).await.unwrap();
            let port = cand.port();
            assert!(
                (30000..=30002).contains(&port.number())
                    || (40000..=40002).contains(&port.number()),
                "Allocated port {port} must be within one of the auto ranges"
            );
            map.bind(port, key);
            allocated.push(port);
        }

        assert_eq!(allocated.len(), 6);
        let mut sorted = allocated.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 6);

        // Pool should now be exhausted
        assert_eq!(
            find_one(&map, &k("overflow"), Port::Tcp(0))
                .await
                .map(|c| c.port()),
            Err(PortError::Exhausted)
        );
    }

    #[tokio::test]
    async fn test_auto_port_exhaustion() {
        let map = PortMap::new(
            vec![PortRange(20000..=20010)],
            vec![PortRange(30000..=30001)],
        );
        let c1 = find_one(&map, &k("r1"), Port::Tcp(0)).await.unwrap();
        let p1 = c1.port();
        map.bind(p1, k("r1"));
        drop(c1);

        let c2 = find_one(&map, &k("r2"), Port::Tcp(0)).await.unwrap();
        map.bind(c2.port(), k("r2"));
        drop(c2);

        assert_eq!(
            find_one(&map, &k("r3"), Port::Tcp(0))
                .await
                .map(|c| c.port()),
            Err(PortError::Exhausted)
        );

        // Unbind frees a slot
        assert_eq!(map.unbind(p1), Some(k("r1")));
        let c3 = find_one(&map, &k("r3"), Port::Tcp(0)).await.unwrap();
        assert_eq!(c3.port(), p1);
    }

    #[test]
    fn test_unbind_port() {
        let map = make_map();
        map.bind(Port::Tcp(20005), k("admin"));
        assert_eq!(map.get_key(Port::Tcp(20005)), Some(k("admin")));

        assert_eq!(map.unbind(Port::Tcp(20005)), Some(k("admin")));
        assert_eq!(map.get_key(Port::Tcp(20005)), None);
    }

    #[tokio::test]
    async fn test_find_free_ports_ordered_locks() {
        let map = make_map();
        let requests = vec![(k("pwn"), Port::Tcp(0)), (k("admin"), Port::Tcp(20005))];

        let candidates = map.find_free_ports(&requests).await.unwrap();
        assert_eq!(candidates.len(), 2);
    }

    #[tokio::test]
    async fn test_find_free_ports_multiple_auto_ports_in_single_batch() {
        let map = make_map();
        let requests = vec![
            (k("web"), Port::Tcp(0)),
            (k("api"), Port::Tcp(0)),
            (k("admin"), Port::Udp(0)),
        ];

        let candidates = map.find_free_ports(&requests).await.unwrap();
        assert_eq!(candidates.len(), 3);
        let p0 = candidates[0].port();
        let p1 = candidates[1].port();
        let p2 = candidates[2].port();

        assert_ne!(p0, p1);
        assert_ne!(p1, p2);
        assert_ne!(p0, p2);
    }

    #[tokio::test]
    async fn test_in_flight_port_is_skipped_by_other_task() {
        let map = Arc::new(PortMap::new(
            vec![],
            vec![PortRange(30000..=30001)], // only 2 ports
        ));

        // Task A acquires port 30000
        let c1 = find_one(&map, &k("task_a"), Port::Tcp(0)).await.unwrap();
        let p1 = c1.port();

        // Task B immediately gets the other port without waiting on task A
        let c2 = find_one(&map, &k("task_b"), Port::Tcp(0)).await.unwrap();
        let p2 = c2.port();

        assert_ne!(p1, p2);

        // Third task finds pool exhausted (both ports in flight)
        assert_eq!(
            find_one(&map, &k("task_c"), Port::Tcp(0))
                .await
                .map(|c| c.port()),
            Err(PortError::Exhausted)
        );

        // When task A finishes/binds and drops guard, 30000 becomes bound
        map.bind(p1, k("task_a"));
        drop(c1);

        // Task A can re-query its own bound port
        let bound = find_one(&map, &k("task_a"), Port::Tcp(0)).await.unwrap();
        assert_eq!(bound.port(), p1);
        assert!(bound.is_bound());
    }

    #[tokio::test]
    async fn test_opposing_multi_port_requests_do_not_deadlock() {
        use std::time::Duration;
        tokio::time::timeout(Duration::from_secs(3), async {
            let map = Arc::new(PortMap::new(
                vec![PortRange(20000..=20010)],
                vec![PortRange(30000..=30010)],
            ));

            let map_a = map.clone();
            let handle_a = tokio::spawn(async move {
                let reqs = vec![(k("a1"), Port::Tcp(20001)), (k("a2"), Port::Tcp(20002))];
                if let Ok(cands) = map_a.find_free_ports(&reqs).await {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    for c in cands {
                        map_a.bind(c.port(), k("team_a"));
                    }
                }
            });

            let map_b = map.clone();
            let handle_b = tokio::spawn(async move {
                // Reverse port order in request
                let reqs = vec![(k("b1"), Port::Tcp(20002)), (k("b2"), Port::Tcp(20001))];
                if let Ok(cands) = map_b.find_free_ports(&reqs).await {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    for c in cands {
                        map_b.bind(c.port(), k("team_b"));
                    }
                }
            });

            let (res_a, res_b) = tokio::join!(handle_a, handle_b);
            assert!(res_a.is_ok());
            assert!(res_b.is_ok());
        })
        .await
        .expect("Test must not deadlock");
    }

    #[tokio::test]
    async fn test_partial_batch_failure_rolls_back_locks() {
        let map = PortMap::new(
            vec![PortRange(20000..=20005)],
            vec![PortRange(30000..=30005)],
        );

        // Port 20001 is valid, but 9999 is invalid/out of range
        let reqs = vec![(k("web"), Port::Tcp(20001)), (k("err"), Port::Tcp(9999))];
        let res = map.find_free_ports(&reqs).await;
        assert_eq!(res.err(), Some(PortError::OutOfRange(Port::Tcp(9999))));

        // Verify port 20001 lock was immediately released and can be acquired
        let res_retry = map.find_free_ports(&[(k("web"), Port::Tcp(20001))]).await;
        assert!(res_retry.is_ok());
    }

    #[tokio::test]
    async fn test_high_concurrency_swarm_stress_no_deadlock() {
        use std::time::Duration;
        tokio::time::timeout(Duration::from_secs(5), async {
            let map = Arc::new(PortMap::new(
                vec![PortRange(20000..=20020)],
                vec![PortRange(30000..=30030)],
            ));

            let mut handles = Vec::new();
            for i in 0..50 {
                let map = map.clone();
                handles.push(tokio::spawn(async move {
                    let team = format!("team-{i}");
                    // Mix of auto and fixed requests
                    let reqs = vec![
                        (k(&format!("{team}-web")), Port::Tcp(0)),
                        (k(&format!("{team}-pwn")), Port::Udp(0)),
                    ];
                    if let Ok(candidates) = map.find_free_ports(&reqs).await {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        for c in candidates {
                            map.bind(c.port(), k(&team));
                        }
                    }
                }));
            }

            for handle in handles {
                assert!(handle.await.is_ok());
            }
        })
        .await
        .expect("High concurrency swarm must complete without deadlocks");
    }

    #[test]
    fn test_clear_namespace() {
        let map = make_map();
        let k1 = ResourceKey::new("team-1", "chal-1", "web");
        let k2 = ResourceKey::new("team-2", "chal-2", "web");

        map.bind(Port::Tcp(20001), k1.clone());
        map.bind(Port::Tcp(20002), k2.clone());

        map.clear_namespace("team-1");

        assert_eq!(map.get_key(Port::Tcp(20001)), None);
        assert_eq!(map.get_key(Port::Tcp(20002)), Some(k2));
    }

    #[test]
    fn test_get_port() {
        let map = make_map();
        let k1 = ResourceKey::new("team-1", "chal-1", "web");
        let k2 = ResourceKey::new("team-1", "chal-1", "pwn");

        map.bind(Port::Tcp(20005), k1.clone());

        assert_eq!(map.get_port(&k1), Some(Port::Tcp(20005)));
        assert_eq!(map.get_port(&k2), None);
    }

    #[test]
    fn test_unbind_key() {
        let map = make_map();
        let k1 = ResourceKey::new("team-1", "chal-1", "web");
        let k2 = ResourceKey::new("team-2", "chal-2", "web");

        map.bind(Port::Tcp(20005), k1.clone());

        // Unbinding with wrong key does nothing
        assert_eq!(map.unbind_key(Port::Tcp(20005), &k2), None);
        assert_eq!(map.get_key(Port::Tcp(20005)), Some(k1.clone()));

        // Unbinding with matching key succeeds
        assert_eq!(map.unbind_key(Port::Tcp(20005), &k1), Some(k1));
        assert_eq!(map.get_key(Port::Tcp(20005)), None);
    }
}

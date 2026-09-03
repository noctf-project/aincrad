use std::collections::BTreeMap;

use k8s_common::PortRange;
use parking_lot::RwLock;

use thiserror::Error;

use crate::cache::ResourceKey;

use super::port_finder::PortFinderFactory;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PortError {
    #[error("port {0} is outside reserved range")]
    OutOfRange(u16),
    #[error("port {0} is already occupied by route '{1}'")]
    Occupied(u16, ResourceKey),
    #[error("auto port pool is exhausted")]
    Exhausted,
}

/// Status of candidate port search for a given resource key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortCandidate {
    /// Port is already bound and owned by this resource key.
    Bound(u16),
    /// Port is available and not yet committed.
    Available(u16),
}

impl PortCandidate {
    /// Returns the port number regardless of whether it is bound or available.
    pub fn port(&self) -> u16 {
        match *self {
            PortCandidate::Bound(p) | PortCandidate::Available(p) => p,
        }
    }
}

struct Inner {
    bindings: BTreeMap<u16, ResourceKey>,
    range_reserved: Vec<PortRange>,
    range_auto: Vec<PortRange>,
    finder: PortFinderFactory,
}

impl Inner {
    fn find_free_port(
        &self,
        key: &ResourceKey,
        requested_port: u16,
    ) -> Result<PortCandidate, PortError> {
        // Fixed port request
        if requested_port != 0 {
            if !self
                .range_reserved
                .iter()
                .any(|r| r.contains(requested_port))
            {
                return Err(PortError::OutOfRange(requested_port));
            }

            if let Some(owner) = self.bindings.get(&requested_port) {
                if owner == key {
                    return Ok(PortCandidate::Bound(requested_port));
                }
                return Err(PortError::Occupied(requested_port, owner.clone()));
            }

            return Ok(PortCandidate::Available(requested_port));
        }

        // Auto port request with existing assignment
        if let Some((&existing_port, _)) = self.bindings.iter().find(|(port, owner)| {
            *owner == key && self.range_auto.iter().any(|r| r.contains(**port))
        }) {
            return Ok(PortCandidate::Bound(existing_port));
        }

        // LCG candidate cycle search across all auto port ranges
        let cycle = self.finder.random_cycle();
        for candidate in cycle {
            if !self.bindings.contains_key(&candidate) {
                return Ok(PortCandidate::Available(candidate));
            }
        }

        Err(PortError::Exhausted)
    }

    fn bind(&mut self, port: u16, key: ResourceKey) {
        // Clear any previous port allocated to this key
        self.bindings.retain(|&p, owner| p == port || *owner != key);
        self.bindings.insert(port, key);
    }

    fn unbind(&mut self, port: u16) -> Option<ResourceKey> {
        self.bindings.remove(&port)
    }

    fn clear(&mut self) {
        self.bindings.clear();
    }
}

/// In-memory port mapping cache providing optimistic candidate lookup via LCG permutations.
pub struct PortMap {
    range_reserved: Vec<PortRange>,
    range_auto: Vec<PortRange>,
    inner: RwLock<Inner>,
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
            range_reserved: reserved.clone(),
            range_auto: auto.clone(),
            inner: RwLock::new(Inner {
                bindings: BTreeMap::new(),
                finder,
                range_reserved: reserved,
                range_auto: auto,
            }),
        }
    }

    /// Checks if a port is within any reserved range without acquiring a lock.
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

    /// Finds a candidate free port using LCG permutation without mutating state.
    pub fn find_free_port(
        &self,
        key: &ResourceKey,
        requested_port: u16,
    ) -> Result<PortCandidate, PortError> {
        self.inner.read().find_free_port(key, requested_port)
    }

    /// Updates mapping with an observed or committed port binding.
    pub fn bind(&self, port: u16, key: ResourceKey) {
        self.inner.write().bind(port, key);
    }

    /// Removes binding for a given port number.
    pub fn unbind(&self, port: u16) -> Option<ResourceKey> {
        self.inner.write().unbind(port)
    }

    /// Gets resource key owning a port if present.
    pub fn get_key(&self, port: u16) -> Option<ResourceKey> {
        self.inner.read().bindings.get(&port).cloned()
    }

    /// Clears all active mappings.
    pub fn clear(&self) {
        self.inner.write().clear();
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

    #[test]
    fn test_find_fixed_port_within_range() {
        let map = make_map();
        let candidate = map.find_free_port(&k("web"), 20001).unwrap();
        assert_eq!(candidate, PortCandidate::Available(20001));

        // Binding marks it as occupied
        map.bind(20001, k("web"));
        assert_eq!(map.get_key(20001), Some(k("web")));

        // Same key finding same port returns Bound
        assert_eq!(
            map.find_free_port(&k("web"), 20001),
            Ok(PortCandidate::Bound(20001))
        );

        // Different key finding occupied port fails
        assert_eq!(
            map.find_free_port(&k("pwn"), 20001),
            Err(PortError::Occupied(20001, k("web")))
        );
    }

    #[test]
    fn test_find_fixed_port_multiple_ranges() {
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

        let c1 = map.find_free_port(&k("svc1"), 1005).unwrap();
        assert_eq!(c1, PortCandidate::Available(1005));

        let c2 = map.find_free_port(&k("svc2"), 8080).unwrap();
        assert_eq!(c2, PortCandidate::Available(8080));
    }

    #[test]
    fn test_find_fixed_port_out_of_range() {
        let map = make_map();
        assert_eq!(
            map.find_free_port(&k("web"), 8080),
            Err(PortError::OutOfRange(8080))
        );
    }

    #[test]
    fn test_find_auto_port_lcg_selection() {
        let map = make_map();
        let c1 = map.find_free_port(&k("pwn"), 0).unwrap();
        let p1 = c1.port();
        assert_eq!(c1, PortCandidate::Available(p1));
        assert!((30000..=30010).contains(&p1));

        map.bind(p1, k("pwn"));

        // Idempotency: same key gets same port as Bound
        assert_eq!(
            map.find_free_port(&k("pwn"), 0),
            Ok(PortCandidate::Bound(p1))
        );

        // Next key gets a different free port as Available
        let c2 = map.find_free_port(&k("web"), 0).unwrap();
        let p2 = c2.port();
        assert_eq!(c2, PortCandidate::Available(p2));
        assert!((30000..=30010).contains(&p2));
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_find_auto_port_multiple_ranges() {
        let map = PortMap::new(
            vec![PortRange(1000..=1010)],
            vec![PortRange(30000..=30002), PortRange(40000..=40002)],
        );

        let mut allocated = Vec::new();
        for i in 0..6 {
            let key = k(&format!("task-{i}"));
            let cand = map.find_free_port(&key, 0).unwrap();
            let port = cand.port();
            assert!(
                (30000..=30002).contains(&port) || (40000..=40002).contains(&port),
                "Allocated port {port} must be within one of the auto ranges"
            );
            map.bind(port, key);
            allocated.push(port);
        }

        assert_eq!(allocated.len(), 6);
        // All 6 ports must be distinct
        let mut sorted = allocated.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 6);

        // Pool should now be exhausted
        assert_eq!(
            map.find_free_port(&k("overflow"), 0),
            Err(PortError::Exhausted)
        );
    }

    #[test]
    fn test_auto_port_exhaustion() {
        let map = PortMap::new(
            vec![PortRange(20000..=20010)],
            vec![PortRange(30000..=30001)],
        );
        let c1 = map.find_free_port(&k("r1"), 0).unwrap();
        map.bind(c1.port(), k("r1"));

        let c2 = map.find_free_port(&k("r2"), 0).unwrap();
        map.bind(c2.port(), k("r2"));

        assert_eq!(map.find_free_port(&k("r3"), 0), Err(PortError::Exhausted));

        // Unbind frees a slot
        assert_eq!(map.unbind(c1.port()), Some(k("r1")));
        let c3 = map.find_free_port(&k("r3"), 0).unwrap();
        assert_eq!(c3, PortCandidate::Available(c1.port()));
    }

    #[test]
    fn test_unbind_port() {
        let map = make_map();
        map.bind(20005, k("admin"));
        assert_eq!(map.get_key(20005), Some(k("admin")));

        assert_eq!(map.unbind(20005), Some(k("admin")));
        assert_eq!(map.get_key(20005), None);
    }
}

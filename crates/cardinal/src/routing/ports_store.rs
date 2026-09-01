use std::collections::BTreeMap;

use k8s_common::PortRange;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::info;

use crate::cache::ResourceKey;

use super::port_finder::PortFinderFactory;

const PORTS: usize = 65536;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PortError {
    #[error("port {0} is outside reserved range")]
    OutOfRange(u16),
    #[error("port {0} is already occupied by route '{1}'")]
    Occupied(u16, ResourceKey),
    #[error("auto port pool is exhausted")]
    Exhausted,
}

struct Inner {
    bindings: Vec<Option<ResourceKey>>,
    mappings: BTreeMap<ResourceKey, u16>,
    range_reserved: PortRange,
    range_auto: PortRange,
    finder: PortFinderFactory,
}

impl Inner {
    fn allocate(&mut self, key: &ResourceKey, port: u16) -> Result<u16, PortError> {
        // Fixed port allocation (port != 0)
        if port != 0 {
            if !self.range_reserved.contains(port) {
                return Err(PortError::OutOfRange(port));
            }

            if let Some(owner) = &self.bindings[port as usize] {
                if owner == key {
                    return Ok(port);
                }
                return Err(PortError::Occupied(port, owner.clone()));
            }

            // Release any previously allocated port for this route
            self.release(key);

            self.bindings[port as usize] = Some(key.clone());
            self.mappings.insert(key.clone(), port);
            return Ok(port);
        }

        // Auto port allocation (port == 0)
        if let Some(&existing_port) = self.mappings.get(key) {
            if self.range_auto.contains(existing_port) {
                return Ok(existing_port);
            }
            self.release(key);
        }

        let cycle = self.finder.cycle(&key.to_string());
        let mut allocated_port = None;

        for candidate in cycle {
            if self.bindings[candidate as usize].is_none() {
                allocated_port = Some(candidate);
                break;
            }
        }

        let candidate = allocated_port.ok_or(PortError::Exhausted)?;
        self.bindings[candidate as usize] = Some(key.clone());
        self.mappings.insert(key.clone(), candidate);
        Ok(candidate)
    }

    fn release(&mut self, key: &ResourceKey) -> Option<u16> {
        if let Some(port) = self.mappings.remove(key) {
            self.bindings[port as usize] = None;
            return Some(port);
        }
        None
    }

    fn release_if_bound(&mut self, key: &ResourceKey, port: u16) -> bool {
        if let Some(&current_port) = self.mappings.get(key)
            && current_port == port
        {
            self.mappings.remove(key);
            self.bindings[port as usize] = None;
            return true;
        }
        false
    }

    fn release_instance(&mut self, namespace: &str, instance: &str) -> Vec<u16> {
        let keys_to_remove: Vec<ResourceKey> = self
            .mappings
            .keys()
            .filter(|k| k.namespace == namespace && k.instance == instance)
            .cloned()
            .collect();

        let mut released = Vec::new();
        for key in keys_to_remove {
            if let Some(port) = self.mappings.remove(&key) {
                self.bindings[port as usize] = None;
                released.push(port);
            }
        }
        released
    }

    fn release_namespace(&mut self, namespace: &str) -> Vec<u16> {
        let keys_to_remove: Vec<ResourceKey> = self
            .mappings
            .keys()
            .filter(|k| k.namespace == namespace)
            .cloned()
            .collect();

        let mut released = Vec::new();
        for key in keys_to_remove {
            if let Some(port) = self.mappings.remove(&key) {
                self.bindings[port as usize] = None;
                released.push(port);
            }
        }
        released
    }

    fn sync(&mut self, key: &ResourceKey, port: u16) {
        if port == 0 {
            self.release(key);
            return;
        }

        let idx = port as usize;
        let old_binding = self.bindings[idx].replace(key.clone());
        let old_port = self.mappings.insert(key.clone(), port);

        if let Some(old_k) = old_binding
            && old_k != *key
        {
            self.mappings.remove(&old_k);
        }

        if let Some(old_p) = old_port
            && old_p != port
        {
            self.bindings[old_p as usize] = None;
        }
    }

    fn clear(&mut self) {
        self.bindings.fill(None);
        self.mappings.clear();
    }

    fn get_port(&self, key: &ResourceKey) -> Option<u16> {
        self.mappings.get(key).copied()
    }

    fn get_route(&self, port: u16) -> Option<ResourceKey> {
        self.bindings[port as usize].clone()
    }

    fn instance_routes(&self, namespace: &str, instance: &str) -> Vec<(ResourceKey, u16)> {
        self.mappings
            .iter()
            .filter(|(k, _)| k.namespace == namespace && k.instance == instance)
            .map(|(k, &p)| (k.clone(), p))
            .collect()
    }

    fn active_ports(&self) -> Vec<u16> {
        self.mappings.values().copied().collect()
    }
}

pub struct PortsStore {
    inner: RwLock<Inner>,
}

impl PortsStore {
    pub fn new(range_reserved: PortRange, range_auto: PortRange) -> Self {
        Self {
            inner: RwLock::new(Inner {
                bindings: vec![None; PORTS],
                mappings: BTreeMap::new(),
                range_reserved,
                range_auto: range_auto.clone(),
                finder: PortFinderFactory::new(&range_auto),
            }),
        }
    }

    /// Allocates a port for a given ResourceKey (port == 0 for auto, port != 0 for fixed).
    pub fn allocate(&self, key: &ResourceKey, port: u16) -> Result<u16, PortError> {
        let mut inner = self.inner.write();
        inner.allocate(key, port)
    }

    /// Releases any port allocated to the given ResourceKey.
    pub fn release(&self, key: &ResourceKey) -> Option<u16> {
        let mut inner = self.inner.write();
        let port = inner.release(key);
        if let Some(p) = port {
            info!("route {key} released port {p}");
        }
        port
    }

    /// Releases all ports allocated to any route belonging to the given namespace and instance.
    pub fn release_instance(&self, namespace: &str, instance: &str) -> Vec<u16> {
        let mut inner = self.inner.write();
        let released = inner.release_instance(namespace, instance);
        for &port in &released {
            info!("instance {namespace}/{instance} released port {port}");
        }
        released
    }

    /// Releases all ports allocated to any route belonging to the given namespace.
    pub fn release_namespace(&self, namespace: &str) -> Vec<u16> {
        let mut inner = self.inner.write();
        let released = inner.release_namespace(namespace);
        for &port in &released {
            info!("namespace {namespace} released port {port}");
        }
        released
    }

    /// Releases the port only if it is currently mapped to this exact port for the given ResourceKey.
    pub fn release_if_bound(&self, key: &ResourceKey, port: u16) -> bool {
        let mut inner = self.inner.write();
        let released = inner.release_if_bound(key, port);
        if released {
            info!("route {key} released port {port}");
        }
        released
    }

    /// Synchronizes an authoritative port assignment observed from external resources.
    pub fn sync(&self, key: &ResourceKey, port: u16) {
        let mut inner = self.inner.write();
        inner.sync(key, port);
    }

    /// Gets the allocated port for a ResourceKey if present.
    pub fn get_port(&self, key: &ResourceKey) -> Option<u16> {
        self.inner.read().get_port(key)
    }

    /// Gets the ResourceKey bound to a port if present.
    pub fn get_route(&self, port: u16) -> Option<ResourceKey> {
        self.inner.read().get_route(port)
    }

    /// Returns all (ResourceKey, port) pairs for a given namespace and instance.
    pub fn instance_routes(&self, namespace: &str, instance: &str) -> Vec<(ResourceKey, u16)> {
        let inner = self.inner.read();
        inner.instance_routes(namespace, instance)
    }

    /// Returns a list of all currently allocated ports.
    pub fn active_ports(&self) -> Vec<u16> {
        self.inner.read().active_ports()
    }

    /// Clears all bindings and mappings.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::ResourceKey;

    use super::*;
    use std::sync::Arc;

    fn k(s: &str) -> ResourceKey {
        ResourceKey {
            namespace: "default".into(),
            instance: "chal-1".into(),
            resource: s.into(),
        }
    }

    fn make_store() -> PortsStore {
        PortsStore::new(PortRange(20000..=20010), PortRange(30000..=30010))
    }

    #[test]
    fn test_allocate_fixed_port_lifecycle() {
        let store = make_store();
        let port = store.allocate(&k("web"), 20001).unwrap();
        assert_eq!(port, 20001);
        assert_eq!(store.get_port(&k("web")), Some(20001));
        assert_eq!(store.get_route(20001), Some(k("web")));

        // Re-allocation for the same key is idempotent
        assert_eq!(store.allocate(&k("web"), 20001), Ok(20001));

        // Release frees the port
        assert_eq!(store.release(&k("web")), Some(20001));
        assert_eq!(store.get_port(&k("web")), None);
        assert_eq!(store.get_route(20001), None);
    }

    #[test]
    fn test_allocate_auto_port_lifecycle() {
        let store = make_store();
        let port = store.allocate(&k("pwn"), 0).unwrap();
        assert!((30000..=30010).contains(&port));
        assert_eq!(store.get_port(&k("pwn")), Some(port));
        assert_eq!(store.get_route(port), Some(k("pwn")));

        // Idempotency: re-requesting auto gives back the existing port
        assert_eq!(store.allocate(&k("pwn"), 0), Ok(port));
    }

    #[test]
    fn test_fixed_port_collision() {
        let store = make_store();
        store.allocate(&k("r1"), 20001).unwrap();
        assert_eq!(
            store.allocate(&k("r2"), 20001),
            Err(PortError::Occupied(20001, k("r1")))
        );
    }

    #[test]
    fn test_fixed_port_out_of_range() {
        let store = make_store();
        assert_eq!(
            store.allocate(&k("r1"), 10000),
            Err(PortError::OutOfRange(10000))
        );
    }

    #[test]
    fn test_auto_port_exhaustion() {
        let store = PortsStore::new(PortRange(20000..=20010), PortRange(30000..=30001));
        store.allocate(&k("r1"), 0).unwrap();
        store.allocate(&k("r2"), 0).unwrap();
        assert_eq!(store.allocate(&k("r3"), 0), Err(PortError::Exhausted));
    }

    #[test]
    fn test_reassign_fixed_to_auto() {
        let store = make_store();
        store.allocate(&k("r1"), 20001).unwrap();
        assert_eq!(store.get_route(20001), Some(k("r1")));

        let auto_port = store.allocate(&k("r1"), 0).unwrap();
        assert!((30000..=30010).contains(&auto_port));
        assert_eq!(store.get_route(20001), None);
        assert_eq!(store.get_route(auto_port), Some(k("r1")));
    }

    #[test]
    fn test_sync_authoritative() {
        let store = make_store();
        store.sync(&k("r1"), 20005);
        assert_eq!(store.get_port(&k("r1")), Some(20005));
        assert_eq!(store.get_route(20005), Some(k("r1")));

        store.sync(&k("r1"), 0);
        assert_eq!(store.get_port(&k("r1")), None);
        assert_eq!(store.get_route(20005), None);
    }

    #[test]
    fn test_active_ports() {
        let store = make_store();
        store.allocate(&k("r1"), 20001).unwrap();
        store.allocate(&k("r2"), 20002).unwrap();

        let mut ports = store.active_ports();
        ports.sort();
        assert_eq!(ports, vec![20001, 20002]);
    }

    #[test]
    fn test_release_if_bound() {
        let store = make_store();
        store.allocate(&k("r1"), 20001).unwrap();

        // Mismatched port should not release
        assert!(!store.release_if_bound(&k("r1"), 20002));
        assert_eq!(store.get_port(&k("r1")), Some(20001));

        // Matching port should release
        assert!(store.release_if_bound(&k("r1"), 20001));
        assert_eq!(store.get_port(&k("r1")), None);
        assert_eq!(store.get_route(20001), None);
    }

    #[test]
    fn test_auto_port_exhaustion_release_reallocate_cycle() {
        let store = PortsStore::new(PortRange(20000..=20010), PortRange(30000..=30001));
        let p1 = store.allocate(&k("r1"), 0).unwrap();
        let p2 = store.allocate(&k("r2"), 0).unwrap();
        assert_ne!(p1, p2);

        // Third allocation exceeds capacity of 2
        assert_eq!(store.allocate(&k("r3"), 0), Err(PortError::Exhausted));

        // Release r1
        assert_eq!(store.release(&k("r1")), Some(p1));

        // r3 can now successfully allocate the freed port
        let p3 = store.allocate(&k("r3"), 0).unwrap();
        assert_eq!(p3, p1);
    }

    #[tokio::test]
    async fn test_high_concurrency_port_contention() {
        use std::collections::HashSet;

        let store = Arc::new(PortsStore::new(
            PortRange(20000..=20010),
            PortRange(30000..=30049),
        ));

        let mut handles = Vec::new();
        for i in 0..50 {
            let store = store.clone();
            let handle = tokio::spawn(async move {
                let key = ResourceKey::new("default", format!("chal-{i}"), "pwn");
                store.allocate(&key, 0)
            });
            handles.push(handle);
        }

        let mut allocated_ports = HashSet::new();
        for handle in handles {
            let res = handle.await.unwrap();
            assert!(res.is_ok(), "Concurrent allocation failed: {:?}", res);
            let port = res.unwrap();
            assert!(
                (30000..=30049).contains(&port),
                "Allocated port out of auto range: {port}"
            );
            assert!(
                allocated_ports.insert(port),
                "Duplicate port allocation detected in concurrent run: {port}"
            );
        }

        assert_eq!(allocated_ports.len(), 50);
        assert_eq!(store.active_ports().len(), 50);
    }

    #[test]
    fn test_release_instance() {
        let store = make_store();
        let k1 = ResourceKey::new("default", "chal-1", "web");
        let k2 = ResourceKey::new("default", "chal-1", "pwn");
        let k3 = ResourceKey::new("default", "chal-2", "web");

        let p1 = store.allocate(&k1, 20001).unwrap();
        let p2 = store.allocate(&k2, 0).unwrap();
        let p3 = store.allocate(&k3, 20002).unwrap();

        assert_eq!(store.active_ports().len(), 3);

        // Release chal-1 (should release k1 and k2, but keep k3)
        let released = store.release_instance("default", "chal-1");
        assert_eq!(released.len(), 2);
        assert!(released.contains(&p1));
        assert!(released.contains(&p2));

        assert_eq!(store.get_port(&k1), None);
        assert_eq!(store.get_port(&k2), None);
        assert_eq!(store.get_port(&k3), Some(p3));
        assert_eq!(store.active_ports(), vec![p3]);
    }

    #[test]
    fn test_instance_routes() {
        let store = make_store();
        let k1 = ResourceKey::new("default", "chal-1", "web");
        let k2 = ResourceKey::new("default", "chal-1", "pwn");
        let k3 = ResourceKey::new("default", "chal-2", "web");

        store.allocate(&k1, 20001).unwrap();
        store.allocate(&k2, 0).unwrap();
        store.allocate(&k3, 20002).unwrap();

        let routes = store.instance_routes("default", "chal-1");
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .any(|(k, p)| k.resource == "web" && *p == 20001)
        );
        assert!(routes.iter().any(|(k, _)| k.resource == "pwn"));
    }

    #[test]
    fn test_release_namespace() {
        let store = make_store();
        let k_ns1_a = ResourceKey::new("team-1", "chal-1", "web");
        let k_ns1_b = ResourceKey::new("team-1", "chal-2", "pwn");
        let k_ns2 = ResourceKey::new("team-2", "chal-1", "web");

        let p1 = store.allocate(&k_ns1_a, 20001).unwrap();
        let p2 = store.allocate(&k_ns1_b, 0).unwrap();
        let p3 = store.allocate(&k_ns2, 20002).unwrap();

        assert_eq!(store.active_ports().len(), 3);

        // Releasing team-1 should release k_ns1_a and k_ns1_b, but preserve team-2's k_ns2
        let released = store.release_namespace("team-1");
        assert_eq!(released.len(), 2);
        assert!(released.contains(&p1));
        assert!(released.contains(&p2));

        assert_eq!(store.get_port(&k_ns1_a), None);
        assert_eq!(store.get_port(&k_ns1_b), None);
        assert_eq!(store.get_port(&k_ns2), Some(p3));
        assert_eq!(store.active_ports(), vec![p3]);
    }
}

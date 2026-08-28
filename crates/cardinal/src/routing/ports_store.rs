use std::collections::HashMap;
use std::sync::RwLock;

use k8s_common::PortRange;
use thiserror::Error;
use tracing::info;

use super::port_finder::PortFinderFactory;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub namespace: String,
    pub name: String,
}

impl std::fmt::Display for RouteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortAllocation<T> {
    Intended(T),
    Pending { current: Option<T>, next: T },
}

const LOCK_POISONED_ERROR: &str = "PortManager bindings lock was poisoned";
const PORTS: usize = 65536;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PortError {
    #[error("port {0} is outside reserved range")]
    OutOfRange(u16),
    #[error("port {0} is already occupied by route '{1}'")]
    Occupied(u16, RouteKey),
    #[error("auto port pool is exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSyncResult {
    Unchanged,
    Added(u16),
    Changed { old: u16, new: u16 },
    Removed(u16),
}

struct Inner {
    bindings: Vec<Option<PortAllocation<RouteKey>>>,
    mappings: HashMap<RouteKey, PortAllocation<u16>>,
    range_auto: PortRange,
    finder: PortFinderFactory,
}

impl Inner {
    fn reserve(
        &mut self,
        spec: &RouteKey,
        port: u16,
    ) -> Result<Option<PortAllocation<u16>>, PortError> {
        // Allocate fixed
        if port != 0 {
            if let Some(allocation) = &self.bindings[port as usize] {
                let owner = match allocation {
                    PortAllocation::Intended(s) => s,
                    PortAllocation::Pending { next, .. } => next,
                };

                if owner == spec {
                    return Ok(self.mappings.get(spec).cloned());
                }
                return Err(PortError::Occupied(port, owner.clone()));
            }

            self.remove_pending(spec);

            let current_port = self.mappings.get(spec).and_then(|a| match a {
                PortAllocation::Intended(p) => Some(*p),
                _ => None,
            });

            self.bindings[port as usize] = Some(PortAllocation::Pending {
                current: current_port.map(|_| spec.clone()),
                next: spec.clone(),
            });

            let alloc = PortAllocation::Pending {
                current: current_port,
                next: port,
            };
            self.mappings.insert(spec.clone(), alloc.clone());
            return Ok(Some(alloc));
        }

        // Allocate auto
        if let Some(existing) = self.mappings.get(spec).cloned() {
            match existing {
                PortAllocation::Intended(p) if self.range_auto.contains(p) => {
                    return Ok(Some(PortAllocation::Intended(p)));
                }
                PortAllocation::Pending {
                    current: Some(c), ..
                } if self.range_auto.contains(c) => {
                    self.remove_pending(spec);
                    return Ok(Some(PortAllocation::Intended(c)));
                }
                PortAllocation::Pending {
                    current: None,
                    next,
                } if self.range_auto.contains(next) => {
                    return Ok(Some(PortAllocation::Pending {
                        current: None,
                        next,
                    }));
                }
                _ => {
                    self.remove_pending(spec);
                }
            }
        }

        let current_port = self.mappings.get(spec).and_then(|a| match a {
            PortAllocation::Intended(p) => Some(*p),
            _ => None,
        });

        let cycle = self.finder.cycle(&spec.to_string());
        let mut allocated_port = None;

        for candidate in cycle {
            if self.bindings[candidate as usize].is_none() {
                allocated_port = Some(candidate);
                break;
            }
        }
        let candidate = allocated_port.ok_or(PortError::Exhausted)?;

        self.bindings[candidate as usize] = Some(PortAllocation::Pending {
            current: current_port.map(|_| spec.clone()),
            next: spec.clone(),
        });

        let alloc = PortAllocation::Pending {
            current: current_port,
            next: candidate,
        };
        self.mappings.insert(spec.clone(), alloc.clone());
        Ok(Some(alloc))
    }

    fn insert(&mut self, spec: &RouteKey, port: Option<u16>) -> PortSyncResult {
        let port = match port {
            Some(0) | None => {
                let old_mapping = self.mappings.get(spec).cloned();
                let removed = self.remove(spec);
                if !removed {
                    return PortSyncResult::Unchanged;
                }
                return match old_mapping {
                    Some(PortAllocation::Intended(p)) => PortSyncResult::Removed(p),
                    Some(PortAllocation::Pending {
                        current: Some(p), ..
                    }) => PortSyncResult::Removed(p),
                    _ => PortSyncResult::Unchanged,
                };
            }
            Some(p) => p,
        };

        let idx = port as usize;

        let old_binding = self.bindings[idx].replace(PortAllocation::Intended(spec.clone()));
        let old_mapping = self
            .mappings
            .insert(spec.clone(), PortAllocation::Intended(port));

        let old_spec = match old_binding {
            Some(PortAllocation::Intended(s)) => Some(s),
            Some(PortAllocation::Pending { next, .. }) => Some(next),
            None => None,
        };

        let (old_port, old_next) = match old_mapping {
            Some(PortAllocation::Intended(p)) => (Some(p), None),
            Some(PortAllocation::Pending { current, next }) => (current, Some(next)),
            None => (None, None),
        };

        if let Some(s) = old_spec
            && s != *spec
            && let Some(PortAllocation::Pending { next, .. }) = self.mappings.remove(&s)
            && next != port
        {
            self.bindings[next as usize] = None;
        }
        if let Some(p) = old_port
            && p != port
        {
            self.bindings[p as usize] = None;
        }
        if let Some(p) = old_next
            && p != port
        {
            self.bindings[p as usize] = None;
        }

        match old_port {
            Some(old_p) if old_p == port => PortSyncResult::Unchanged,
            Some(old_p) => PortSyncResult::Changed {
                old: old_p,
                new: port,
            },
            None => PortSyncResult::Added(port),
        }
    }

    fn remove_pending(&mut self, spec: &RouteKey) -> bool {
        if matches!(
            self.mappings.get(spec),
            Some(PortAllocation::Pending { .. })
        ) && let Some(PortAllocation::Pending { current, next }) = self.mappings.remove(spec)
        {
            self.bindings[next as usize] = None;

            if let Some(current_port) = current {
                self.mappings
                    .insert(spec.clone(), PortAllocation::Intended(current_port));
                self.bindings[current_port as usize] = Some(PortAllocation::Intended(spec.clone()));
            }
            return true;
        }
        false
    }

    fn remove(&mut self, spec: &RouteKey) -> bool {
        if let Some(mapping) = self.mappings.remove(spec) {
            match mapping {
                PortAllocation::Intended(port) => {
                    self.bindings[port as usize] = None;
                }
                PortAllocation::Pending { current, next } => {
                    self.bindings[next as usize] = None;
                    if let Some(current_port) = current {
                        self.bindings[current_port as usize] = None;
                    }
                }
            }
            return true;
        }
        false
    }

    fn clear_pending(&mut self) {
        let Inner {
            bindings, mappings, ..
        } = self;
        mappings.retain(|spec, allocation| match allocation {
            PortAllocation::Intended(_) => true,
            PortAllocation::Pending { current, next } => {
                bindings[*next as usize] = None;

                if let Some(current_port) = current {
                    bindings[*current_port as usize] = Some(PortAllocation::Intended(spec.clone()));
                    *allocation = PortAllocation::Intended(*current_port);
                    true
                } else {
                    false
                }
            }
        });
    }

    pub fn clear(&mut self) {
        self.bindings.fill(None);
        self.mappings.clear();
    }

    fn get(&self, port: u16) -> Option<PortAllocation<RouteKey>> {
        self.bindings[port as usize].clone()
    }

    fn active_route(&self, port: u16) -> Option<RouteKey> {
        self.bindings[port as usize].as_ref().and_then(|a| match a {
            PortAllocation::Intended(a) => Some(a.clone()),
            PortAllocation::Pending { current, .. } => current.clone(),
        })
    }

    fn active_ports(&self) -> Vec<u16> {
        self.mappings
            .values()
            .filter_map(|allocation| match allocation {
                PortAllocation::Intended(port) => Some(*port),
                PortAllocation::Pending {
                    current: Some(current_port),
                    ..
                } => Some(*current_port),
                PortAllocation::Pending { current: None, .. } => None,
            })
            .collect()
    }

    fn get_route(&self, key: &RouteKey) -> Option<PortAllocation<u16>> {
        self.mappings.get(key).cloned()
    }
}

pub struct PortsStore {
    range_reserved: PortRange,
    range_auto: PortRange,
    inner: RwLock<Inner>,
}

impl PortsStore {
    pub fn new(range_reserved: PortRange, range_auto: PortRange) -> Self {
        Self {
            range_reserved,
            range_auto: range_auto.clone(),
            inner: RwLock::new(Inner {
                bindings: vec![None; PORTS],
                mappings: HashMap::new(),
                range_auto: range_auto.clone(),
                finder: PortFinderFactory::new(&range_auto),
            }),
        }
    }

    /// Reserves a port. This is a proposal so only needs to be called from the leader.
    pub fn reserve(
        &self,
        spec: &RouteKey,
        port: Option<u16>,
    ) -> Result<Option<PortAllocation<u16>>, PortError> {
        let port = match port {
            Some(p) => p,
            None => {
                let mut table = self.inner.write().expect(LOCK_POISONED_ERROR);
                table.remove_pending(spec);
                return Ok(None);
            }
        };

        // Only allocate reserved port in reserved range
        if port != 0 && !self.range_reserved.contains(port) {
            return Err(PortError::OutOfRange(port));
        }

        let mut table = self.inner.write().expect(LOCK_POISONED_ERROR);
        table.reserve(spec, port)
    }

    /// Commits a port from an authoritative source into the tracking array.
    /// This will overwrite the existing allocation and should be called authoritatively.
    pub fn insert(&self, spec: &RouteKey, port: Option<u16>) -> PortSyncResult {
        let mut table = self.inner.write().expect(LOCK_POISONED_ERROR);
        let result = table.insert(spec, port);
        match &result {
            PortSyncResult::Added(p) => {
                info!("route {spec} bound port {p}")
            }
            PortSyncResult::Changed { old, new } => {
                info!("route {spec} swapped from {old} -> {new}")
            }
            PortSyncResult::Removed(p) => {
                info!("route {spec} unbound port {p}")
            }
            _ => (),
        }
        result
    }

    /// Removes a pending port from the table and return it.
    #[cfg(test)]
    fn remove_pending(&self, spec: &RouteKey) -> bool {
        let mut table = self.inner.write().expect(LOCK_POISONED_ERROR);
        table.remove_pending(spec)
    }

    /// Clears pending ports
    pub fn clear_pending(&self) {
        let mut table = self.inner.write().expect(LOCK_POISONED_ERROR);
        table.clear_pending();
    }

    /// Clear all ports
    pub fn clear(&self) {
        let mut inner = self.inner.write().expect(LOCK_POISONED_ERROR);
        inner.clear();
    }

    /// Gets the allocation (Active or Pending) if it exists.
    #[allow(dead_code)]
    pub fn get(&self, port: u16) -> Option<PortAllocation<RouteKey>> {
        if !self.range_reserved.contains(port) && !self.range_auto.contains(port) {
            return None;
        }
        self.inner.read().expect(LOCK_POISONED_ERROR).get(port)
    }

    #[allow(dead_code)]
    pub fn get_route(&self, key: &RouteKey) -> Option<PortAllocation<u16>> {
        self.inner.read().expect(LOCK_POISONED_ERROR).get_route(key)
    }

    /// Returns the spec only if the service is Active
    pub fn active_route(&self, port: u16) -> Option<RouteKey> {
        if !self.range_reserved.contains(port) && !self.range_auto.contains(port) {
            return None;
        }
        self.inner
            .read()
            .expect(LOCK_POISONED_ERROR)
            .active_route(port)
    }

    /// Get active ports to listen on
    pub fn active_ports(&self) -> Vec<u16> {
        self.inner.read().expect(LOCK_POISONED_ERROR).active_ports()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> RouteKey {
        RouteKey {
            namespace: "default".into(),
            name: s.into(),
        }
    }

    fn make_pm() -> PortsStore {
        PortsStore::new(PortRange(20000..=20010), PortRange(30000..=30010))
    }

    #[test]
    fn test_reserve_none() {
        let pm = make_pm();
        pm.reserve(&k("r1"), Some(20001)).unwrap();
        assert_eq!(pm.reserve(&k("r1"), None), Ok(None));
        assert_eq!(pm.get(20001), None);
    }

    #[test]
    fn test_out_of_range() {
        let pm = make_pm();
        assert_eq!(
            pm.reserve(&k("r1"), Some(10000)),
            Err(PortError::OutOfRange(10000))
        );
    }

    #[test]
    fn test_fixed_port_lifecycle() {
        let pm = make_pm();
        let alloc = pm.reserve(&k("r1"), Some(20001)).unwrap().unwrap();
        assert_eq!(
            alloc,
            PortAllocation::Pending {
                current: None,
                next: 20001
            }
        );
        assert_eq!(pm.active_route(20001), None);

        pm.insert(&k("r1"), Some(20001));
        assert_eq!(pm.active_route(20001), Some(k("r1")));
    }

    #[test]
    fn test_auto_port_lifecycle() {
        let pm = make_pm();
        let alloc = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        let next_port = match alloc {
            PortAllocation::Pending {
                current: None,
                next,
            } => next,
            _ => panic!("expected Pending with current: None"),
        };
        assert!(pm.range_auto.contains(next_port));

        pm.insert(&k("r1"), Some(next_port));
        assert_eq!(pm.active_route(next_port), Some(k("r1")));
    }

    #[test]
    fn test_sync_none_deletes() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        assert_eq!(pm.active_route(20001), Some(k("r1")));

        pm.insert(&k("r1"), None);
        assert_eq!(pm.active_route(20001), None);
        assert_eq!(pm.get(20001), None);
    }

    #[test]
    fn test_fixed_port_collision() {
        let pm = make_pm();
        pm.reserve(&k("r1"), Some(20001)).unwrap();
        assert_eq!(
            pm.reserve(&k("r2"), Some(20001)),
            Err(PortError::Occupied(20001, k("r1")))
        );
    }

    #[test]
    fn test_auto_port_exhaustion() {
        let pm = PortsStore::new(PortRange(20000..=20010), PortRange(30000..=30001));
        pm.reserve(&k("r1"), Some(0)).unwrap();
        pm.reserve(&k("r2"), Some(0)).unwrap();
        assert_eq!(pm.reserve(&k("r3"), Some(0)), Err(PortError::Exhausted));
    }

    #[test]
    fn test_port_swap_conflict() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        pm.insert(&k("r2"), Some(20002));
        assert_eq!(
            pm.reserve(&k("r1"), Some(20002)),
            Err(PortError::Occupied(20002, k("r2")))
        );
    }

    #[test]
    fn test_reserve_idempotency() {
        let pm = make_pm();
        let res1 = pm.reserve(&k("r1"), Some(20001)).unwrap();
        let res2 = pm.reserve(&k("r1"), Some(20001)).unwrap();
        assert_eq!(res1, res2);

        let res3 = pm.reserve(&k("r2"), Some(0)).unwrap();
        let res4 = pm.reserve(&k("r2"), Some(0)).unwrap();
        assert_eq!(res3, res4);
    }

    #[test]
    fn test_reassign_auto_to_fixed() {
        let pm = make_pm();
        let alloc = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        let auto_port = match alloc {
            PortAllocation::Pending { next, .. } => next,
            _ => panic!("expected Pending"),
        };
        pm.insert(&k("r1"), Some(auto_port));

        pm.reserve(&k("r1"), Some(20001)).unwrap();
        pm.insert(&k("r1"), Some(20001));

        assert_eq!(pm.active_route(20001), Some(k("r1")));
        assert_eq!(pm.active_route(auto_port), None);
    }

    #[test]
    fn test_reassign_fixed_to_auto() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));

        let alloc = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        let next_port = match alloc {
            PortAllocation::Pending {
                current: Some(20001),
                next,
            } => next,
            _ => panic!("expected Pending with current: Some(20001)"),
        };
        assert!(pm.range_auto.contains(next_port));
        pm.insert(&k("r1"), Some(next_port));

        assert_eq!(pm.active_route(next_port), Some(k("r1")));
        assert_eq!(pm.active_route(20001), None);
    }

    #[test]
    fn test_rapid_uncommitted_proposal_changes() {
        let pm = make_pm();
        pm.reserve(&k("r1"), Some(20001)).unwrap();
        pm.reserve(&k("r1"), Some(20002)).unwrap();
        pm.reserve(&k("r1"), Some(20003)).unwrap();

        assert_eq!(pm.get(20001), None);
        assert_eq!(pm.get(20002), None);
        assert_eq!(
            pm.get(20003),
            Some(PortAllocation::Pending {
                current: None,
                next: k("r1")
            })
        );
    }

    #[test]
    fn test_revert_uncommitted_to_active_auto() {
        let pm = make_pm();
        let alloc = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        let auto_port = match alloc {
            PortAllocation::Pending { next, .. } => next,
            _ => panic!("expected Pending"),
        };
        pm.insert(&k("r1"), Some(auto_port));

        pm.reserve(&k("r1"), Some(20001)).unwrap();
        let reverted = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        assert_eq!(reverted, PortAllocation::Intended(auto_port));
        assert_eq!(pm.get(20001), None);
    }

    #[test]
    fn test_remove_pending_rollback() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        pm.reserve(&k("r1"), Some(20002)).unwrap();

        assert!(pm.remove_pending(&k("r1")));
        assert_eq!(pm.active_route(20001), Some(k("r1")));
        assert_eq!(pm.get(20002), None);
    }

    #[test]
    fn test_clear_pending_failover() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        pm.reserve(&k("r1"), Some(20002)).unwrap();
        pm.reserve(&k("r2"), Some(20003)).unwrap();

        pm.clear_pending();

        assert_eq!(pm.active_route(20001), Some(k("r1")));
        assert_eq!(pm.get(20002), None);
        assert_eq!(pm.get(20003), None);
    }

    #[test]
    fn test_post_failover_sync_healing() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        pm.reserve(&k("r1"), Some(20002)).unwrap();

        pm.clear_pending();
        assert_eq!(pm.active_route(20001), Some(k("r1")));

        pm.insert(&k("r1"), Some(20002));
        assert_eq!(pm.active_route(20002), Some(k("r1")));
        assert_eq!(pm.active_route(20001), None);
    }

    #[test]
    fn test_sync_steals_pending_port() {
        let pm = make_pm();
        pm.reserve(&k("r1"), Some(20001)).unwrap();
        pm.insert(&k("r2"), Some(20001));

        assert_eq!(pm.active_route(20001), Some(k("r2")));
    }

    #[test]
    fn test_get_vs_active_route() {
        let pm = make_pm();
        pm.reserve(&k("r1"), Some(20001)).unwrap();

        assert_eq!(
            pm.get(20001),
            Some(PortAllocation::Pending {
                current: None,
                next: k("r1")
            })
        );
        assert_eq!(pm.active_route(20001), None);

        pm.insert(&k("r1"), Some(20001));
        assert_eq!(pm.get(20001), Some(PortAllocation::Intended(k("r1"))));
        assert_eq!(pm.active_route(20001), Some(k("r1")));
    }

    #[test]
    fn test_active_ports_mappings() {
        let pm = make_pm();
        pm.insert(&k("r1"), Some(20001));
        pm.insert(&k("r2"), Some(30005));

        let mut ports = pm.active_ports();
        ports.sort();
        assert_eq!(ports, vec![20001, 30005]);
    }

    #[test]
    fn test_port_zero_is_auto() {
        let pm = make_pm();
        let alloc = pm.reserve(&k("r1"), Some(0)).unwrap().unwrap();
        match alloc {
            PortAllocation::Pending {
                current: None,
                next,
            } => {
                assert!(pm.range_auto.contains(next));
            }
            _ => panic!("expected Pending with current: None"),
        }
    }

    #[test]
    fn test_sync_over_pending_clears_next_binding() {
        let pm = make_pm();

        pm.reserve(&k("r1"), Some(20002)).unwrap();
        pm.insert(&k("r1"), Some(20001));

        assert_eq!(pm.active_route(20001), Some(k("r1")));
        assert_eq!(pm.get(20002), None);
        assert_eq!(
            pm.reserve(&k("r2"), Some(20002)),
            Ok(Some(PortAllocation::Pending {
                current: None,
                next: 20002
            }))
        );
    }

    #[test]
    fn test_sync_port_zero_ignored() {
        let pm = make_pm();
        let res = pm.insert(&k("r1"), Some(0));
        assert_eq!(res, PortSyncResult::Unchanged);
        assert!(!pm.active_ports().contains(&0));
        assert_eq!(pm.active_route(0), None);
    }

    #[test]
    fn test_sync_displacing_spec_with_pending_next_clears_ghost_binding() {
        let pm = make_pm();

        pm.insert(&k("r1"), Some(20001));
        pm.reserve(&k("r1"), Some(20002)).unwrap();

        pm.insert(&k("r2"), Some(20001));

        assert_eq!(pm.get(20002), None);
        assert_eq!(
            pm.reserve(&k("r3"), Some(20002)),
            Ok(Some(PortAllocation::Pending {
                current: None,
                next: 20002
            }))
        );
    }
}

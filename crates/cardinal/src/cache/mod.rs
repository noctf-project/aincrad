pub mod instance;
pub mod resource;
pub mod template;

pub use instance::{InstanceCache, InstanceKey};
pub use resource::{CachedItem, ResourceCache, ResourceEntry, ResourceKey, ResourceProjection};
pub use template::{CachedTemplateEntry, PodPatchersMap, TemplateCache, TemplateKey};

use k8s_common::crd::TLSRoute;
use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::Service;
use tokio::sync::watch;

/// Aggregated in-memory caches for every managed resource kind.
#[derive(Clone, Default)]
pub struct Caches {
    pub templates: TemplateCache,
    pub instances: InstanceCache,
    pub replica_sets: ResourceCache<ReplicaSet>,
    pub services: ResourceCache<Service>,
    pub tls_routes: ResourceCache<TLSRoute>,
}

/// A cache that can report whether its backing watcher has finished its
/// initial sync.
pub trait ReadyCache: Send + Sync {
    /// `true` once the cache has been populated by an initial watcher sync.
    fn is_ready(&self) -> bool;

    /// A receiver that turns `true` when the cache becomes ready. The watch
    /// stores the latest value, so late subscribers observe an already-ready
    /// cache immediately.
    fn watch(&self) -> watch::Receiver<bool>;
}

/// Gates instance processing until all given caches complete their initial sync.
///
/// Reads readiness off the caches, so it is agnostic to how many watchers there
/// are and safe to reuse across controllers.
#[derive(Clone)]
pub struct ReadyGate {
    rxs: Vec<watch::Receiver<bool>>,
}

impl ReadyGate {
    /// Builds a gate over the caches whose readiness the controller depends on.
    pub fn from_caches(caches: &Caches) -> Self {
        Self {
            rxs: vec![
                caches.templates.watch(),
                caches.services.watch(),
                caches.replica_sets.watch(),
                caches.tls_routes.watch(),
            ],
        }
    }

    /// Waits until every watched cache reports ready. Returns once all are
    /// synced; safe to call from multiple tasks.
    pub async fn wait(&self) {
        for rx in &self.rxs {
            let mut rx = rx.clone();
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    /// `true` if every watched cache is currently ready.
    pub fn is_ready(&self) -> bool {
        self.rxs.iter().all(|rx| *rx.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn caches() -> Caches {
        Caches::default()
    }

    fn mark_all_ready(caches: &Caches) {
        caches.templates.mark_ready();
        caches.services.mark_ready();
        caches.replica_sets.mark_ready();
        caches.tls_routes.mark_ready();
    }

    #[test]
    fn test_gate_starts_unready() {
        let gate = ReadyGate::from_caches(&caches());
        assert!(!gate.is_ready());
    }

    #[tokio::test]
    async fn test_gate_waits_until_last_cache_marks_ready() {
        let caches = caches();
        let gate = ReadyGate::from_caches(&caches);

        // Three of four caches synced; gate must stay closed.
        caches.services.mark_ready();
        caches.replica_sets.mark_ready();
        caches.tls_routes.mark_ready();
        assert!(!gate.is_ready());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), gate.wait())
                .await
                .is_err(),
            "gate must not open before templates sync"
        );

        let gate_wait = gate.clone();
        let waiter = tokio::spawn(async move { gate_wait.wait().await });

        // Still pending, then the last cache flips and it opens.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let finished = waiter.is_finished();
        caches.templates.mark_ready();

        assert!(
            !finished,
            "waiter must still be pending before the last sync"
        );
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("gate must open once every cache reports ready")
            .unwrap();
        assert!(gate.is_ready());
    }

    #[tokio::test]
    async fn test_gate_opens_immediately_when_all_caches_already_ready() {
        let caches = caches();
        mark_all_ready(&caches);

        let gate = ReadyGate::from_caches(&caches);
        assert!(gate.is_ready());
        tokio::time::timeout(Duration::from_secs(1), gate.wait())
            .await
            .expect("a fully-synced gate must not block");
    }

    #[test]
    fn test_gate_is_independent_per_controller() {
        // Two controllers sharing the same caches each build their own gate;
        // both open when the shared caches sync.
        let caches = caches();
        let gate_a = ReadyGate::from_caches(&caches);
        let gate_b = ReadyGate::from_caches(&caches);

        mark_all_ready(&caches);
        assert!(gate_a.is_ready());
        assert!(gate_b.is_ready());
    }

    #[test]
    fn test_gate_tracks_unready_across_watcher_resync() {
        let caches = caches();
        let gate = ReadyGate::from_caches(&caches);
        mark_all_ready(&caches);
        assert!(gate.is_ready());

        // A watcher restarts its initial sync; the gate must close again.
        caches.services.mark_unready();
        assert!(!gate.is_ready());

        // Re-sync reopens it.
        caches.services.mark_ready();
        assert!(gate.is_ready());
    }

    #[tokio::test]
    async fn test_gate_wait_resumes_after_resync_unready_period() {
        let caches = caches();
        mark_all_ready(&caches);
        let gate = ReadyGate::from_caches(&caches);

        // Push one cache back to unready, then re-ready it quickly; the gate
        // wait must resume and finish.
        caches.replica_sets.mark_unready();
        let gate_wait = gate.clone();
        let waiter = tokio::spawn(async move { gate_wait.wait().await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        caches.replica_sets.mark_ready();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("wait must resume once the cache re-syncs")
            .unwrap();
    }

    #[test]
    fn test_gate_order_of_ready_marks_does_not_matter() {
        let caches = caches();
        let gate = ReadyGate::from_caches(&caches);
        // Mark in reverse order; still opens once all four are ready.
        caches.tls_routes.mark_ready();
        caches.replica_sets.mark_ready();
        caches.services.mark_ready();
        assert!(!gate.is_ready());
        caches.templates.mark_ready();
        assert!(gate.is_ready());
    }

    #[test]
    fn test_gate_receiver_tracks_latched_caches_without_polling() {
        let caches = caches();
        let gate = ReadyGate::from_caches(&caches);
        assert!(!gate.is_ready());

        // Pre-subscribed receiver must flip as soon as the last cache syncs.
        let rx = caches.templates.watch();
        caches.templates.mark_ready();
        assert!(*rx.borrow());
    }
}

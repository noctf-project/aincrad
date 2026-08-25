use std::{iter::Peekable, sync::Arc};

use kube::{ResourceExt, runtime::watcher::Event};

use crate::store::routes::MetadataAndSpec;

pub trait Dedupable {
    fn should_dedup(&self, next: &Self) -> bool;
}

pub struct DedupLast<I>
where
    I: Iterator,
{
    iter: Peekable<I>,
}

impl<T: ?Sized + Dedupable> Dedupable for &T {
    fn should_dedup(&self, next: &Self) -> bool {
        (**self).should_dedup(*next)
    }
}

impl<I> Iterator for DedupLast<I>
where
    I: Iterator,
    I::Item: Dedupable,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(current) = self.iter.next() {
            if let Some(next) = self.iter.peek()
                && current.should_dedup(next)
            {
                continue; // Skip earlier duplicates to reach the latest
            }
            return Some(current);
        }
        None
    }
}

#[allow(dead_code)]
pub struct DedupFirst<I>
where
    I: Iterator,
{
    iter: Peekable<I>,
}

impl<I> Iterator for DedupFirst<I>
where
    I: Iterator,
    I::Item: Dedupable,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.iter.next()?;

        // Eagerly consume all consecutive duplicates that match `current`
        while let Some(next) = self.iter.peek() {
            if current.should_dedup(next) {
                self.iter.next();
            } else {
                break;
            }
        }

        Some(current)
    }
}

pub trait DedupExt: Iterator + Sized {
    /// Keeps the first element in each consecutive duplicate run.
    #[allow(dead_code)]
    fn dedup_first(self) -> DedupFirst<Self>
    where
        Self::Item: Dedupable,
    {
        DedupFirst {
            iter: self.peekable(),
        }
    }

    /// Keeps the last element in each consecutive duplicate run.
    fn dedup_last(self) -> DedupLast<Self>
    where
        Self::Item: Dedupable,
    {
        DedupLast {
            iter: self.peekable(),
        }
    }
}

impl<I: Iterator> DedupExt for I {}

impl<T: ?Sized + Dedupable> Dedupable for Arc<T> {
    fn should_dedup(&self, next: &Self) -> bool {
        Arc::ptr_eq(self, next) || (**self).should_dedup(&**next)
    }
}

impl<T> Dedupable for Event<T>
where
    T: ResourceExt,
{
    fn should_dedup(&self, next: &Self) -> bool {
        let (curr, next) = match (self, next) {
            (
                Event::Apply(a) | Event::Delete(a) | Event::InitApply(a),
                Event::Apply(b) | Event::Delete(b) | Event::InitApply(b),
            ) => (a, b),
            _ => return false,
        };
        match (&curr.meta().uid, &next.meta().uid) {
            (Some(u1), Some(u2)) => u1 == u2,
            // If either UID is missing, resource identity cannot be guaranteed.
            // Downstream accounting and state tracking rely strictly on UID equality,
            // so we return false to avoid accidentally dropping distinct events.
            _ => false,
        }
    }
}

impl Dedupable for MetadataAndSpec {
    fn should_dedup(&self, next: &Self) -> bool {
        self.uid == next.uid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_common::crd::{CTFRoute, CTFRouteBackend, CTFRouteSpec};
    use kube::core::ObjectMeta;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct Item {
        id: u32,
        val: &'static str,
    }

    impl Dedupable for Item {
        fn should_dedup(&self, next: &Self) -> bool {
            self.id == next.id
        }
    }

    #[test]
    fn test_dedup_first_empty_and_single() {
        let empty: Vec<Item> = vec![];
        let res: Vec<_> = empty.into_iter().dedup_first().collect();
        assert!(res.is_empty());

        let single = vec![Item { id: 1, val: "a" }];
        let res: Vec<_> = single.into_iter().dedup_first().collect();
        assert_eq!(res, vec![Item { id: 1, val: "a" }]);
    }

    #[test]
    fn test_dedup_first_consecutive_duplicates() {
        let items = vec![
            Item { id: 1, val: "a1" },
            Item { id: 1, val: "a2" },
            Item { id: 1, val: "a3" },
            Item { id: 2, val: "b1" },
            Item { id: 2, val: "b2" },
            Item { id: 3, val: "c1" },
            Item { id: 1, val: "a4" },
        ];
        let res: Vec<_> = items.into_iter().dedup_first().collect();
        assert_eq!(
            res,
            vec![
                Item { id: 1, val: "a1" },
                Item { id: 2, val: "b1" },
                Item { id: 3, val: "c1" },
                Item { id: 1, val: "a4" },
            ]
        );
    }

    #[test]
    fn test_dedup_last_empty_and_single() {
        let empty: Vec<Item> = vec![];
        let res: Vec<_> = empty.into_iter().dedup_last().collect();
        assert!(res.is_empty());

        let single = vec![Item { id: 1, val: "a" }];
        let res: Vec<_> = single.into_iter().dedup_last().collect();
        assert_eq!(res, vec![Item { id: 1, val: "a" }]);
    }

    #[test]
    fn test_dedup_last_consecutive_duplicates() {
        let items = vec![
            Item { id: 1, val: "a1" },
            Item { id: 1, val: "a2" },
            Item { id: 1, val: "a3" },
            Item { id: 2, val: "b1" },
            Item { id: 2, val: "b2" },
            Item { id: 3, val: "c1" },
            Item { id: 1, val: "a4" },
        ];
        let res: Vec<_> = items.into_iter().dedup_last().collect();
        assert_eq!(
            res,
            vec![
                Item { id: 1, val: "a3" },
                Item { id: 2, val: "b2" },
                Item { id: 3, val: "c1" },
                Item { id: 1, val: "a4" },
            ]
        );
    }

    #[test]
    fn test_dedup_references() {
        let item1 = Item { id: 1, val: "a1" };
        let item2 = Item { id: 1, val: "a2" };
        let item3 = Item { id: 2, val: "b1" };

        let refs = vec![&item1, &item2, &item3];
        let res_first: Vec<_> = refs.clone().into_iter().dedup_first().collect();
        assert_eq!(res_first, vec![&item1, &item3]);

        let res_last: Vec<_> = refs.into_iter().dedup_last().collect();
        assert_eq!(res_last, vec![&item2, &item3]);
    }

    #[test]
    fn test_dedup_arc() {
        let arc1 = Arc::new(Item { id: 1, val: "a1" });
        let arc2 = Arc::new(Item { id: 1, val: "a2" });
        let arc3 = Arc::new(Item { id: 2, val: "b1" });

        // Test pointer equality fast-path
        assert!(arc1.should_dedup(&arc1));
        // Test value equality
        assert!(arc1.should_dedup(&arc2));
        assert!(!arc1.should_dedup(&arc3));

        let arcs = vec![arc1.clone(), arc2.clone(), arc3.clone()];
        let res_first: Vec<_> = arcs.clone().into_iter().dedup_first().collect();
        assert_eq!(res_first.len(), 2);
        assert_eq!(res_first[0].val, "a1");
        assert_eq!(res_first[1].val, "b1");

        let res_last: Vec<_> = arcs.into_iter().dedup_last().collect();
        assert_eq!(res_last.len(), 2);
        assert_eq!(res_last[0].val, "a2");
        assert_eq!(res_last[1].val, "b1");
    }

    #[test]
    fn test_dedup_metadata_and_spec() {
        let m1 = MetadataAndSpec {
            name: "route-1".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 1,
            observed_generation: None,
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "svc1".into(),
                    port: 80,
                },
                ..Default::default()
            },
        };
        let m2 = MetadataAndSpec {
            name: "route-1".into(),
            namespace: "default".into(),
            uid: "uid-1".into(),
            generation: 2,
            observed_generation: Some(1),
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "svc1".into(),
                    port: 8080,
                },
                ..Default::default()
            },
        };
        let m3 = MetadataAndSpec {
            name: "route-2".into(),
            namespace: "default".into(),
            uid: "uid-2".into(),
            generation: 1,
            observed_generation: None,
            spec: CTFRouteSpec {
                backend: CTFRouteBackend {
                    service: "svc2".into(),
                    port: 80,
                },
                ..Default::default()
            },
        };

        assert!(m1.should_dedup(&m2));
        assert!(!m1.should_dedup(&m3));

        let routes = vec![m1.clone(), m2.clone(), m3.clone()];
        let res_last: Vec<_> = routes.into_iter().dedup_last().collect();
        assert_eq!(res_last.len(), 2);
        assert_eq!(res_last[0].generation, 2);
        assert_eq!(res_last[1].uid, "uid-2");
    }

    #[test]
    fn test_dedup_event_with_uids() {
        let route1 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("r1".into()),
                namespace: Some("default".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };
        let route2 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("r1".into()),
                namespace: Some("default".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };
        let route3 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("r2".into()),
                namespace: Some("default".into()),
                uid: Some("uid-2".into()),
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };

        let ev1 = Event::Apply(route1);
        let ev2 = Event::Delete(route2);
        let ev3 = Event::Apply(route3);
        let ev_init = Event::<CTFRoute>::Init;

        assert!(ev1.should_dedup(&ev2));
        assert!(!ev1.should_dedup(&ev3));
        assert!(!ev1.should_dedup(&ev_init));

        let events = vec![ev1, ev2, ev3];
        let res_last: Vec<_> = events.into_iter().dedup_last().collect();
        assert_eq!(res_last.len(), 2);
        assert!(matches!(res_last[0], Event::Delete(_)));
    }

    #[test]
    fn test_dedup_event_missing_uids() {
        // Events with missing UIDs should return false
        let r1 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("route-a".into()),
                namespace: Some("default".into()),
                uid: None,
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };
        let r2 = CTFRoute {
            metadata: ObjectMeta {
                name: Some("route-a".into()),
                namespace: Some("default".into()),
                uid: None,
                ..Default::default()
            },
            spec: CTFRouteSpec::default(),
            status: None,
        };

        let ev1 = Event::Apply(r1);
        let ev2 = Event::Apply(r2);

        // Missing UIDs mean they should not be deduplicated
        assert!(!ev1.should_dedup(&ev2));
    }
}

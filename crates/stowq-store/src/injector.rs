//! Fault injector wrapping any `ObjectStore`. Fails calls per a scripted
//! plan: pre-transmit (safe blind retry), post-transmit-ambiguous (outcome
//! unknown, caller must resolve), or committed-but-response-lost (outcome
//! unknown with the key present on re-read), at chosen call indexes.
//! Deterministic and inspectable so tests can assert exactly which
//! injections fired.

use crate::{
    Ambiguity, Digest, Key, Meta, Object, ObjectStore, Page, PutOutcome, StoreError, StoreResult,
    TransportClass, Version,
};
use bytes::Bytes;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// One injected failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Fails before the request is transmitted; retrying the identical
    /// call is safe.
    PreTransmit,
    /// Fails after transmit without the store applying the call; the
    /// target key is absent on re-read.
    PostTransmit,
    /// The store applies the call and the response is lost; the caller
    /// sees OutcomeUnknown but the target key is present on re-read.
    /// This is the committed-but-response-lost branch of outcome
    /// resolution.
    PostTransmitAfter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    PutIfAbsent,
    Cas,
    Get,
    Head,
    List,
    Delete,
}

/// What the injector does with a call.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Pass,
    Fail(StoreError),
    FailAfter,
}

/// Which calls a fault applies to.
#[derive(Debug, Clone)]
pub struct FaultPlan {
    op: Op,
    /// Zero-based call indexes to fail, in call order.
    at: Vec<usize>,
    fault: Fault,
}

impl FaultPlan {
    pub fn new(op: Op, fault: Fault, at: impl IntoIterator<Item = usize>) -> Self {
        FaultPlan {
            op,
            at: at.into_iter().collect(),
            fault,
        }
    }
}

struct PlanState {
    /// Number of matching calls seen so far.
    count: usize,
    /// Indexes still to fire, kept sorted; the head is consumed when hit.
    remaining: Vec<usize>,
    fired: usize,
}

pub struct Injector<S> {
    store: S,
    plans: Mutex<Vec<(FaultPlan, PlanState)>>,
    calls: AtomicUsize,
}

impl<S: ObjectStore> Injector<S> {
    pub fn new(store: S, plans: Vec<FaultPlan>) -> Self {
        Injector {
            store,
            plans: Mutex::new(
                plans
                    .into_iter()
                    .map(|p| {
                        let mut at = p.at.clone();
                        at.sort_unstable();
                        at.dedup();
                        let state = PlanState {
                            count: 0,
                            remaining: at,
                            fired: 0,
                        };
                        (p, state)
                    })
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn inner(&self) -> &S {
        &self.store
    }

    /// Total calls that passed through the injector.
    pub fn total_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Faults fired so far, by plan position.
    pub fn fired(&self) -> Vec<usize> {
        self.plans
            .lock()
            .unwrap()
            .iter()
            .map(|(_, s)| s.fired)
            .collect()
    }

    /// Decides this call's fate. At most one fault fires per call: the
    /// first plan (in construction order) whose op matches and whose
    /// index is due. A faulted call returns immediately, so later
    /// same-op plans never see it; they count only surviving calls.
    fn check(&self, op: Op) -> Action {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut plans = self.plans.lock().unwrap();
        for (plan, state) in plans.iter_mut() {
            if plan.op != op {
                continue;
            }
            let this_call = state.count;
            state.count += 1;
            if state.remaining.first() == Some(&this_call) {
                state.remaining.remove(0);
                state.fired += 1;
                return match plan.fault {
                    Fault::PreTransmit => {
                        Action::Fail(StoreError::Transport(TransportClass::PreTransmit))
                    }
                    Fault::PostTransmit => {
                        Action::Fail(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
                    }
                    Fault::PostTransmitAfter => Action::FailAfter,
                };
            }
        }
        Action::Pass
    }
}

impl<S: ObjectStore> ObjectStore for Injector<S> {
    fn put_if_absent(&self, key: &Key, body: Bytes, sha256: Digest) -> StoreResult<PutOutcome> {
        match self.check(Op::PutIfAbsent) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                // The write may have committed (Committed) or lost the
                // race (Rejected); either way the response is lost.
                let _ = self.store.put_if_absent(key, body, sha256)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.put_if_absent(key, body, sha256),
        }
    }

    fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: Digest,
        if_match: &Version,
    ) -> StoreResult<PutOutcome> {
        match self.check(Op::Cas) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                let _ = self.store.cas(key, body, sha256, if_match)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.cas(key, body, sha256, if_match),
        }
    }

    fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        match self.check(Op::Get) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                let _ = self.store.get(key, range)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.get(key, range),
        }
    }

    fn head(&self, key: &Key) -> StoreResult<Meta> {
        match self.check(Op::Head) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                let _ = self.store.head(key)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.head(key),
        }
    }

    fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
        match self.check(Op::List) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                let _ = self.store.list(prefix, after, limit)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.list(prefix, after, limit),
        }
    }

    fn delete(&self, key: &Key) -> StoreResult<()> {
        match self.check(Op::Delete) {
            Action::Fail(e) => Err(e),
            Action::FailAfter => {
                self.store.delete(key)?;
                Err(StoreError::OutcomeUnknown(Ambiguity::ConnectionLost))
            }
            Action::Pass => self.store.delete(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;
    use sha2::{Digest as _, Sha256};

    fn digest(b: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn pre_transmit_fault_is_retry_safe() {
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(Op::PutIfAbsent, Fault::PreTransmit, [0])],
        );
        let k = Key::new("jobs/0001/a");
        let body = Bytes::from_static(b"one");
        let d = digest(b"one");
        assert_eq!(
            injector.put_if_absent(&k, body.clone(), d).unwrap_err(),
            StoreError::Transport(TransportClass::PreTransmit)
        );
        assert!(matches!(
            injector.put_if_absent(&k, body, d).unwrap(),
            PutOutcome::Committed { .. }
        ));
        assert_eq!(injector.fired(), vec![1]);
        assert_eq!(injector.total_calls(), 2);
    }

    #[test]
    fn post_transmit_fault_is_outcome_unknown_and_absent() {
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(Op::PutIfAbsent, Fault::PostTransmit, [0])],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        assert_eq!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"x"), d)
                .unwrap_err(),
            StoreError::OutcomeUnknown(Ambiguity::ConnectionLost)
        );
        // Resolution: absent, so a blind retry is safe.
        assert_eq!(injector.inner().head(&k).unwrap_err(), StoreError::NotFound);
        assert!(matches!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"x"), d)
                .unwrap(),
            PutOutcome::Committed { .. }
        ));
    }

    #[test]
    fn post_transmit_after_is_unknown_but_committed() {
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(
                Op::PutIfAbsent,
                Fault::PostTransmitAfter,
                [0],
            )],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        assert_eq!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"x"), d)
                .unwrap_err(),
            StoreError::OutcomeUnknown(Ambiguity::ConnectionLost)
        );
        // Resolution: the key IS present; a blind retry would see Rejected.
        let meta = injector.inner().head(&k).unwrap();
        assert_eq!(meta.size, 1);
        assert_eq!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"x"), d)
                .unwrap(),
            PutOutcome::Rejected
        );
    }

    #[test]
    fn faults_fire_only_at_planned_indexes() {
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(Op::Get, Fault::PreTransmit, [1, 3])],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        injector
            .put_if_absent(&k, Bytes::from_static(b"x"), d)
            .unwrap();
        assert!(injector.get(&k, None).is_ok()); // call 0
        assert!(injector.get(&k, None).is_err()); // call 1 fires
        assert!(injector.get(&k, None).is_ok()); // call 2
        assert!(injector.get(&k, None).is_err()); // call 3 fires
        assert!(injector.get(&k, None).is_ok()); // call 4
        assert_eq!(injector.fired(), vec![2]);
    }

    #[test]
    fn rejected_put_is_ok_not_error() {
        let inner = MemoryStore::new();
        let injector = Injector::new(inner, vec![]);
        let k = Key::new("jobs/0001/a");
        let d = digest(b"one");
        assert!(matches!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"one"), d)
                .unwrap(),
            PutOutcome::Committed { .. }
        ));
        assert_eq!(
            injector
                .put_if_absent(&k, Bytes::from_static(b"two"), digest(b"two"))
                .unwrap(),
            PutOutcome::Rejected
        );
    }

    #[test]
    fn plans_are_op_scoped() {
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(Op::Delete, Fault::PreTransmit, [0])],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        injector
            .put_if_absent(&k, Bytes::from_static(b"x"), d)
            .unwrap();
        assert!(injector.get(&k, None).is_ok());
        assert!(injector.head(&k).is_ok());
        assert_eq!(
            injector.delete(&k).unwrap_err(),
            StoreError::Transport(TransportClass::PreTransmit)
        );
    }

    #[test]
    fn one_fault_per_call_and_same_op_plans_count_survivors() {
        // Two plans on Get: plan A faults call 0; plan B counts every
        // call that reaches it and faults its own index 1, which is the
        // second call to survive plan A (the third Get overall).
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![
                FaultPlan::new(Op::Get, Fault::PreTransmit, [0]),
                FaultPlan::new(Op::Get, Fault::PostTransmit, [1]),
            ],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        injector
            .put_if_absent(&k, Bytes::from_static(b"x"), d)
            .unwrap();
        assert!(injector.get(&k, None).is_err()); // A fires; B counts 0.
        assert!(injector.get(&k, None).is_ok()); // B counts 1.
        assert!(injector.get(&k, None).is_err()); // B's index 1 due; fires.
        assert!(injector.get(&k, None).is_ok());
        assert_eq!(injector.fired(), vec![1, 1]);
    }
}

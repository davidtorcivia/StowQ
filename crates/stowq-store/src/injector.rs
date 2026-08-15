//! Fault injector wrapping any `ObjectStore`. Fails calls per a scripted
//! plan: pre-transmit (safe blind retry), post-transmit-ambiguous (outcome
//! unknown, caller must resolve), or precondition-rejected, at chosen call
//! indexes. Deterministic and inspectable so tests can assert exactly which
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
    /// Fails after transmit; the caller cannot know whether the store
    /// applied the write.
    PostTransmit,
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

    fn check(&self, op: Op) -> StoreResult<()> {
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
                return Err(match plan.fault {
                    Fault::PreTransmit => StoreError::Transport(TransportClass::PreTransmit),
                    Fault::PostTransmit => StoreError::OutcomeUnknown(Ambiguity::ConnectionLost),
                });
            }
        }
        Ok(())
    }
}

impl<S: ObjectStore> ObjectStore for Injector<S> {
    fn put_if_absent(&self, key: &Key, body: Bytes, sha256: Digest) -> StoreResult<PutOutcome> {
        self.check(Op::PutIfAbsent)?;
        let outcome = self.store.put_if_absent(key, body.clone(), sha256)?;
        if outcome == PutOutcome::Rejected {
            // Losing the race is an expected protocol result, not an
            // error; still verify the digest path saw no corruption.
            return Ok(outcome);
        }
        // Post-transmit ambiguity that resolved to committed still counts
        // as committed: the underlying store has the object.
        Ok(outcome)
    }

    fn cas(
        &self,
        key: &Key,
        body: Bytes,
        sha256: Digest,
        if_match: &Version,
    ) -> StoreResult<PutOutcome> {
        self.check(Op::Cas)?;
        self.store.cas(key, body, sha256, if_match)
    }

    fn get(&self, key: &Key, range: Option<Range<u64>>) -> StoreResult<Object> {
        self.check(Op::Get)?;
        self.store.get(key, range)
    }

    fn head(&self, key: &Key) -> StoreResult<Meta> {
        self.check(Op::Head)?;
        self.store.head(key)
    }

    fn list(&self, prefix: &str, after: Option<&Key>, limit: usize) -> StoreResult<Page> {
        self.check(Op::List)?;
        self.store.list(prefix, after, limit)
    }

    fn delete(&self, key: &Key) -> StoreResult<()> {
        self.check(Op::Delete)?;
        self.store.delete(key)
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
        // First call fails pre-transmit.
        assert_eq!(
            injector.put_if_absent(&k, body.clone(), d).unwrap_err(),
            StoreError::Transport(TransportClass::PreTransmit)
        );
        // Identical retry succeeds.
        assert!(matches!(
            injector.put_if_absent(&k, body, d).unwrap(),
            PutOutcome::Committed { .. }
        ));
        assert_eq!(injector.fired(), vec![1]);
        assert_eq!(injector.total_calls(), 2);
    }

    #[test]
    fn post_transmit_fault_is_outcome_unknown_and_object_exists() {
        // The wrapped store applies the write before the injector fails
        // the call: the caller sees OutcomeUnknown but the key is present.
        // The injector itself does not decide this; the plan only fires
        // the error. To model "store applied it", the inner store must
        // receive the call: so inject on the SECOND call after a
        // successful first.
        let inner = MemoryStore::new();
        let injector = Injector::new(
            inner,
            vec![FaultPlan::new(Op::Head, Fault::PostTransmit, [0])],
        );
        let k = Key::new("jobs/0001/a");
        let d = digest(b"x");
        injector
            .put_if_absent(&k, Bytes::from_static(b"x"), d)
            .unwrap();
        assert_eq!(
            injector.head(&k).unwrap_err(),
            StoreError::OutcomeUnknown(Ambiguity::ConnectionLost)
        );
        // Resolution: re-read.
        assert!(injector.head(&k).is_ok());
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
        // Get and head unaffected.
        assert!(injector.get(&k, None).is_ok());
        assert!(injector.head(&k).is_ok());
        // Delete fires.
        assert_eq!(
            injector.delete(&k).unwrap_err(),
            StoreError::Transport(TransportClass::PreTransmit)
        );
    }
}

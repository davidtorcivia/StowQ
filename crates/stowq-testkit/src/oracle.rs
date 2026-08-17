//! The logical oracle: a pure in-memory model of the queue protocol,
//! written independently of stowq-core so that implementation bugs do
//! not correlate with model bugs. The differential driver runs the same
//! operation sequence through both and asserts equivalence after every
//! step.

use std::collections::HashMap;

/// A terminal state for a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    Receipt,
    Dead { reason: u64 },
}

/// The model's phase for one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Claimable at any floor at or after `not_before` (job-level
    /// delay only; backoffs are their own phase).
    Ready {
        not_before: u64,
    },
    /// Held by a claim expiring at `expiry`, at `generation` /
    /// `attempt`.
    Claimed {
        generation: u64,
        attempt: u64,
        expiry: u64,
    },
    /// Nacked; claimable again at `not_before` with attempt+1.
    Backoff {
        generation: u64,
        attempt: u64,
        not_before: u64,
    },
    Terminal(Terminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobState {
    pub maximum_attempts: u64,
    pub phase: Phase,
    /// Digest of the job's committed output, once written through the
    /// commit rule. Immutable from then on: the store's first-wins
    /// bytes are the only possible value.
    pub output: Option<[u8; 32]>,
}

/// What the oracle expects a driver operation to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    Enqueue(bool),
    Claim(Option<(u64, u64)>),
    Renew(bool),
    Ack(bool),
    Ok,
}

#[derive(Debug, Default)]
pub struct Oracle {
    pub jobs: HashMap<[u8; 16], JobState>,
    /// The logical clock the driver advances; floors come from it.
    pub clock: u64,
}

impl Oracle {
    pub fn new() -> Self {
        Oracle::default()
    }

    pub fn advance_clock_to(&mut self, ns: u64) {
        self.clock = self.clock.max(ns);
    }

    /// Spec idempotent enqueue: absent commits; an identical existing
    /// record (the driver always sends the same envelope per job id)
    /// also reports committed; only a conflicting record is taken.
    pub fn enqueue(&mut self, job_id: [u8; 16], maximum_attempts: u64, not_before: u64) -> bool {
        match self.jobs.get(&job_id) {
            None => {
                self.jobs.insert(
                    job_id,
                    JobState {
                        maximum_attempts,
                        phase: Phase::Ready { not_before },
                        output: None,
                    },
                );
                true
            }
            Some(existing) => existing.maximum_attempts == maximum_attempts,
        }
    }

    /// Whether `claim` would succeed right now, without mutating.
    pub fn can_claim(&self, job_id: &[u8; 16]) -> bool {
        let clock = self.clock;
        let Some(state) = self.jobs.get(job_id) else {
            return false;
        };
        let maximum_attempts = state.maximum_attempts;
        match &state.phase {
            Phase::Ready { not_before } => clock >= *not_before,
            Phase::Backoff {
                attempt,
                not_before,
                ..
            } => clock >= *not_before && *attempt < maximum_attempts,
            Phase::Claimed {
                attempt, expiry, ..
            } => clock >= *expiry && *attempt < maximum_attempts,
            Phase::Terminal(_) => false,
        }
    }

    /// `base` is the store time of the claim object; expiry is
    /// base + lease, per spec (the store clock, not the driver's).
    /// The exhaustion transition the core performs as a side effect of
    /// the claim scan: a job whose next takeover would exceed
    /// maximum_attempts goes dead with attempts_exhausted. The driver
    /// calls this in scan order before consulting can_claim.
    pub fn exhaust_if_due(&mut self, job_id: &[u8; 16]) -> bool {
        let clock = self.clock;
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        let maximum_attempts = state.maximum_attempts;
        let due = match &state.phase {
            Phase::Claimed {
                attempt, expiry, ..
            } => clock >= *expiry && attempt + 1 > maximum_attempts,
            Phase::Backoff {
                attempt,
                not_before,
                ..
            } => clock >= *not_before && attempt + 1 > maximum_attempts,
            _ => false,
        };
        if due {
            state.phase = Phase::Terminal(Terminal::Dead { reason: 0x0004 });
        }
        due
    }

    pub fn claim(
        &mut self,
        job_id: &[u8; 16],
        lease_duration_ns: u64,
        base: u64,
    ) -> Option<(u64, u64)> {
        let clock = self.clock;
        let state = self.jobs.get_mut(job_id)?;
        let maximum_attempts = state.maximum_attempts;
        match state.phase.clone() {
            Phase::Ready { not_before } if clock >= not_before => {
                let generation = 1;
                let attempt = 1;
                let expiry = base.saturating_add(lease_duration_ns);
                state.phase = Phase::Claimed {
                    generation,
                    attempt,
                    expiry,
                };
                Some((generation, attempt))
            }
            Phase::Backoff {
                generation,
                attempt,
                not_before,
            } if clock >= not_before && attempt < maximum_attempts => {
                let generation = generation + 1;
                let attempt = attempt + 1;
                let expiry = base.saturating_add(lease_duration_ns);
                state.phase = Phase::Claimed {
                    generation,
                    attempt,
                    expiry,
                };
                Some((generation, attempt))
            }
            Phase::Claimed {
                generation,
                attempt,
                expiry,
            } if clock >= expiry => {
                if attempt + 1 > maximum_attempts {
                    state.phase = Phase::Terminal(Terminal::Dead { reason: 0x0004 });
                    return None;
                }
                let generation = generation + 1;
                let attempt = attempt + 1;
                let expiry = base.saturating_add(lease_duration_ns);
                state.phase = Phase::Claimed {
                    generation,
                    attempt,
                    expiry,
                };
                Some((generation, attempt))
            }
            _ => None,
        }
    }

    pub fn renew(&mut self, job_id: &[u8; 16], lease_duration_ns: u64) -> bool {
        let clock = self.clock;
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        match state.phase.clone() {
            Phase::Claimed {
                generation,
                attempt,
                expiry: _,
            } => {
                // Renewal after expiry may lose to a takeover; the model
                // treats renewal-before-driver-takeover as winning only
                // when the driver has not taken over. The driver tells
                // the oracle which generation it renewed; generation
                // advances, attempt holds, expiry refreshes.
                let expiry = clock.saturating_add(lease_duration_ns);
                state.phase = Phase::Claimed {
                    generation: generation + 1,
                    attempt,
                    expiry,
                };
                true
            }
            _ => false,
        }
    }

    /// Corrects the held claim's expiry from the observed store time of
    /// the claim object the core just wrote.
    pub fn override_expiry(&mut self, job_id: &[u8; 16], base: u64, lease_duration_ns: u64) {
        if let Some(state) = self.jobs.get_mut(job_id) {
            if let Phase::Claimed { expiry, .. } = &mut state.phase {
                *expiry = base.saturating_add(lease_duration_ns);
            }
        }
    }

    pub fn ack(&mut self, job_id: &[u8; 16]) -> bool {
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        match state.phase {
            Phase::Claimed { .. } => {
                state.phase = Phase::Terminal(Terminal::Receipt);
                true
            }
            Phase::Terminal(Terminal::Receipt) => false, // already acked
            _ => false,
        }
    }

    /// Records a commit-rule output write. Allowed only while a
    /// claim is held (the harness discipline); returns false without
    /// recording otherwise.
    pub fn commit_output(&mut self, job_id: &[u8; 16], digest: [u8; 32]) -> bool {
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        match state.phase {
            Phase::Claimed { .. } => {
                if state.output.is_none() {
                    state.output = Some(digest);
                }
                true
            }
            _ => false,
        }
    }

    /// The committed output digest for a job, if any.
    pub fn output_digest(&self, job_id: &[u8; 16]) -> Option<[u8; 32]> {
        self.jobs.get(job_id).and_then(|s| s.output)
    }

    pub fn nack(&mut self, job_id: &[u8; 16], not_before: u64) -> bool {
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        match state.phase.clone() {
            Phase::Claimed {
                generation,
                attempt,
                expiry: _,
            } => {
                state.phase = Phase::Backoff {
                    generation,
                    attempt,
                    not_before,
                };
                true
            }
            _ => false,
        }
    }

    pub fn bury(&mut self, job_id: &[u8; 16], reason: u64) -> bool {
        let Some(state) = self.jobs.get_mut(job_id) else {
            return false;
        };
        // Spec: the holder buries. Custody is required.
        match state.phase {
            Phase::Claimed { .. } => {
                state.phase = Phase::Terminal(Terminal::Dead { reason });
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_ready_job() {
        let mut o = Oracle::new();
        o.enqueue([1; 16], 3, 0);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), Some((1, 1)));
        // Not expired at the same clock.
        assert_eq!(o.claim(&[1; 16], 1_000, 0), None);
        o.advance_clock_to(1_000);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), Some((2, 2)));
    }

    #[test]
    fn exhaustion_writes_dead() {
        let mut o = Oracle::new();
        o.enqueue([1; 16], 1, 0);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), Some((1, 1)));
        o.advance_clock_to(1_000);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), None);
        assert_eq!(
            o.jobs[&[1; 16]].phase,
            Phase::Terminal(Terminal::Dead { reason: 0x0004 })
        );
    }

    #[test]
    fn backoff_then_takeover() {
        let mut o = Oracle::new();
        o.enqueue([1; 16], 3, 0);
        o.claim(&[1; 16], 1_000, 0);
        assert!(o.nack(&[1; 16], 500));
        // Before backoff elapses: nothing.
        o.advance_clock_to(499);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), None);
        o.advance_clock_to(500);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), Some((2, 2)));
    }

    #[test]
    fn renew_refreshes_without_attempt() {
        let mut o = Oracle::new();
        o.enqueue([1; 16], 2, 0);
        o.claim(&[1; 16], 1_000, 0);
        assert!(o.renew(&[1; 16], 1_000));
        assert_eq!(
            o.jobs[&[1; 16]].phase,
            Phase::Claimed {
                generation: 2,
                attempt: 1,
                expiry: 1_000
            }
        );
    }

    #[test]
    fn delayed_not_claimable_early() {
        let mut o = Oracle::new();
        o.enqueue([1; 16], 3, 10_000);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), None);
        o.advance_clock_to(10_000);
        assert_eq!(o.claim(&[1; 16], 1_000, 0), Some((1, 1)));
    }
}

# Claims model

`StowQClaims.tla` models the claim chain of one job: first claim,
expiry-driven takeover with basis evidence, renewal by the holder with
custody continuity, and exhaustion writing dead. Workers have no local
state — any worker may attempt any action at any step, which subsumes
the crash and ambiguity adversary: a crashed or response-blind worker
is no more constrained than a stateless one, and the store arbitrates
regardless of what the worker knows. The put-if-absent race is encoded
structurally: an action writes a generation above the current tail, so
no contender writes the same generation twice.

Time is a single monotone logical clock shared by all participants (the
floor). A claim's store time is the floor at its write; lease expiry is
`floor >= time + Dur`. The skew guard is modeled at zero, matching the
implementation's default; it only widens the expiry threshold and does
not interact with the invariants below.

## Invariants checked

- `TypeOK`
- `GenerationsMonotonic`: generations are contiguous from 1 — no gaps,
  so the chain is exactly the write history.
- `OneWinnerPerGeneration`: at most one record per (job, generation).
- `AdmissibleTakeoverBasis`: every takeover above generation 1 carries
  basis evidence proving the previous generation expired.
- `AdmissibleContinuationCustody`: every continuation continues the
  previous generation's holder.
- `AttemptWithinLimit`
- `DeadFollowsExhaustion`: within this model's action set, dead records
  appear only through exhaustion of a maximum-attempt expired tail
  (bury writes dead at any attempt; the terminal model covers that
  path).

## Configuration

Two workers, one job, `MaxGen = 4`, `MaxAttempt = 2`, `Dur = 2`,
`TimeMax = 8`; unbounded worker nondeterminism (no fairness needed for
the invariants). 13,765 distinct states, exhaustive, ~1s.

## Omissions

- Receipts and outputs (covered by the terminal model).
- Backoff gating between nack and takeover: the fail record's
  `retry_not_before` only delays takeovers and cannot violate any
  invariant above; modeled as absent.
- Store faults: transport ambiguity resolves within one conditional
  write, so the store's arbitration is already the model's whole
  semantics; injected faults exercise the implementation, not the
  protocol's state space.
- Skew guard and store-clock granularity: constant widening of the
  expiry threshold only.

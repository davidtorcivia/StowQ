# Terminal model

`StowQTerminal.tla` models the terminal path of one job: the commit
rule (deterministic outputs written put-if-absent before the receipt),
acknowledgment with first-wins receipts, burial, and their mutual
exclusion. Workers have no local state; a zombie is any worker acting
after its lease expired or its custody was superseded. The receipt's
content is deterministic given the job, so receipt stability and zombie
harmlessness reduce to state invariants over one fixed record.
Stability itself (a receipt or output is never cleared or rewritten)
is structural: no action does either.

## Invariants checked

- `TypeOK`
- `AtMostOneTerminalRecord`: receipt and dead never coexist under the
  model's atomic transitions — the guard discipline, both directions
  (ack refuses under dead; bury refuses under receipt). The store-level
  property has a check-then-act window the model's atomicity cannot
  represent: ack and bury write different keys, both put-if-absent, so
  the pre-write checks minimize but cannot close it. A pair produced by
  the window is a repair-scan quarantine finding (see
  ../recovery.md errata).
- `OutputsPrecedeReceipt`: a receipt implies its outputs exist — the
  commit rule's visibility half.
- `ClaimsBoundedByTerminal`: within this model's horizon, claims never
  outlive terminalization (retention GC deletes claims before the
  terminal record in the full protocol).

## Configuration

Two workers, `MaxGen = 4`, `Dur = 2`, `TimeMax = 8`. 77,338 distinct
states, exhaustive, ~1s.

## Omissions

- Multiple jobs: the invariants are per-job and job-independent; the
  claims model covers cross-job structure at the chain level.
- Output digest conflicts (`0x0011` quarantine): deterministic content
  makes conflicts unrepresentable here; the implementation's conflict
  path is exercised by the fault suite.
- Payload evidence re-verification: modeled as always available; the
  implementation's verify-before-terminal-write is tested directly.
- Temporal (eventual) properties: liveness under the protocol's
  fairness assumption is carried by the contract, not this model.

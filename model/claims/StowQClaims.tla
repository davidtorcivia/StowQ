------------------------------- MODULE StowQClaims -------------------------------
EXTENDS Naturals, TLC

(***************************************************************************)
(* StowQ/1 claim-chain model.                                             *)
(*                                                                         *)
(* The store is the sole arbiter: claim keys are jobs/<shard>/<job>/<gen>  *)
(* written put-if-absent, so exactly one contender per generation wins.    *)
(* Workers are modeled with no local state: any worker may attempt any     *)
(* action at any step, which subsumes the crash and ambiguity adversary    *)
(* (a crashed or response-blind worker is no more constrained than a       *)
(* stateless one; the store arbitrates regardless of what the worker       *)
(* knows). Store time is a single monotone logical clock, the floor.       *)
(* Every claim's store time is the floor at its write, and lease expiry    *)
(* is floor >= time + Dur.                                                *)
(***************************************************************************)

CONSTANTS W,            \* workers
          J,            \* jobs
          MaxGen,       \* generation bound
          MaxAttempt,   \* attempt bound (takeovers only)
          Dur,          \* fixed lease duration in ticks
          TimeMax       \* clock bound

VARIABLES claims,   \* set of claim records
          dead,     \* set of jobs with dead records
          floor     \* the shared store-time floor

ClaimRec == [ job: J,
              gen: 1..MaxGen,
              worker: W,
              attempt: 1..MaxAttempt,
              cont: BOOLEAN,           \* continuation (renewal) or takeover
              basis: 0..TimeMax,       \* observed floor at a takeover write
              time: 0..TimeMax ]       \* store time at the write

Vars == <<claims, dead, floor>>

GensOf(j) == {r.gen : r \in {r \in claims : r.job = j}}

TailOf(j) == CHOOSE t \in {r \in claims : r.job = j} :
               \A s \in {r \in claims : r.job = j} : s.gen <= t.gen

HasTail(j) == \E r \in claims : r.job = j

Init == /\ claims = {}
        /\ dead = {}
        /\ floor = 0

Tick == /\ floor < TimeMax
        /\ floor' = floor + 1
        /\ UNCHANGED <<claims, dead>>

(*************************************************************************)
(* A takeover: the tail is expired, attempts remain, and the claimant    *)
(* writes generation tail.gen + 1 with basis evidence. The put-if-absent *)
(* race is encoded structurally: the action writes a generation above    *)
(* the current tail, so no contender can write the same generation       *)
(* twice (the tail would already include it).                           *)
(*************************************************************************)
TakeOver(j) ==
    /\ j \notin dead
    /\ HasTail(j)
    /\ LET tail == TailOf(j)
       IN  /\ tail.gen < MaxGen
           /\ floor >= tail.time + Dur          \* expiry
           /\ tail.attempt + 1 <= MaxAttempt    \* attempts remain
           /\ \E w \in W :
                /\ claims' = claims \union { [ job    |-> j,
                                               gen    |-> tail.gen + 1,
                                               worker |-> w,
                                               attempt |-> tail.attempt + 1,
                                               cont   |-> FALSE,
                                               basis  |-> floor,
                                               time   |-> floor ] }
    /\ UNCHANGED <<dead, floor>>

(*************************************************************************)
(* The first claim of a live job.                                        *)
(*************************************************************************)
FirstClaim(j) ==
    /\ j \notin dead
    /\ ~HasTail(j)
    /\ 1 <= MaxAttempt
    /\ \E w \in W :
         claims' = claims \union { [ job    |-> j,
                                     gen    |-> 1,
                                     worker |-> w,
                                     attempt |-> 1,
                                     cont   |-> FALSE,
                                     basis  |-> floor,
                                     time   |-> floor ] }
    /\ UNCHANGED <<dead, floor>>

(*************************************************************************)
(* A renewal: the current holder extends custody with a continuation     *)
(* claim at generation tail.gen + 1. Custody continuity is the           *)
(* worker match; the store's put-if-absent decides a race with a         *)
(* takeover by whichever action commits generation tail.gen + 1 first    *)
(* (the loser's generation is no longer the tail, so its action is       *)
(* disabled in the next state).                                         *)
(*************************************************************************)
Renew(j, w) ==
    /\ j \notin dead
    /\ HasTail(j)
    /\ LET tail == TailOf(j)
       IN  /\ tail.gen < MaxGen
           /\ tail.worker = w                 \* custody
           /\ claims' = claims \union { [ job    |-> j,
                                          gen    |-> tail.gen + 1,
                                          worker |-> w,
                                          attempt |-> tail.attempt,
                                          cont   |-> TRUE,
                                          basis  |-> 0,
                                          time   |-> floor ] }
    /\ UNCHANGED <<dead, floor>>

(*************************************************************************)
(* Attempts exhausted: the takeover that would exceed the bound writes   *)
(* dead instead of a claim.                                              *)
(*************************************************************************)
Exhaust(j) ==
    /\ j \notin dead
    /\ HasTail(j)
    /\ LET tail == TailOf(j)
       IN  /\ tail.attempt = MaxAttempt
           /\ floor >= tail.time + Dur
           /\ dead' = dead \union {j}
           /\ UNCHANGED <<claims, floor>>

\* Legitimate quiescent states (clock capped, tail unexpired, attempts
\* exhausted) have no protocol action; an explicit stutter keeps them
\* non-dead.
NoOp == UNCHANGED Vars

Next == Tick \/ NoOp
        \/ \E j \in J : TakeOver(j) \/ FirstClaim(j) \/ Exhaust(j) \/ \E w \in W : Renew(j, w)

Spec == Init /\ [][Next]_Vars

(*************************************************************************)
(* Invariants                                                            *)
(***************************************************************************)

TypeOK ==
    /\ claims \subseteq ClaimRec
    /\ dead \subseteq J
    /\ floor \in 0..TimeMax

\* Generations are contiguous from 1: no gaps, so the chain is exactly
\* the write history and strictly increasing.
GenerationsMonotonic ==
    \A j \in J : HasTail(j) => GensOf(j) = 1..TailOf(j).gen

\* The put-if-absent linearization: at most one winner per (job, gen).
OneWinnerPerGeneration ==
    \A r1, r2 \in claims :
        (r1.job = r2.job /\ r1.gen = r2.gen) => r1 = r2

\* Takeover evidence: a non-continuation claim above generation 1 is
\* admissible iff its recorded basis proves the previous generation was
\* expired at the takeover.
AdmissibleTakeoverBasis ==
    \A r \in {r \in claims : ~r.cont /\ r.gen > 1} :
        LET prev == CHOOSE p \in {p \in claims : p.job = r.job /\ p.gen = r.gen - 1} : TRUE
        IN  r.basis >= prev.time + Dur

\* Continuation custody: a renewal continues the previous generation's
\* holder.
AdmissibleContinuationCustody ==
    \A r \in {r \in claims : r.cont} :
        LET prev == CHOOSE p \in {p \in claims : p.job = r.job /\ p.gen = r.gen - 1} : TRUE
        IN  r.worker = prev.worker

AttemptWithinLimit == \A r \in claims : r.attempt <= MaxAttempt

\* Dead records only appear through exhaustion of a maximum-attempt tail.
DeadFollowsExhaustion ==
    \A j \in dead : HasTail(j) /\ TailOf(j).attempt = MaxAttempt

=============================================================================

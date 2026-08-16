------------------------------- MODULE StowQTerminal -------------------------------
EXTENDS Naturals, TLC

(***************************************************************************)
(* StowQ/1 terminal model: receipt first-wins, receipt/dead mutual         *)
(* exclusion, idempotent re-ack, and the commit rule for outputs.          *)
(*                                                                         *)
(* One job; workers have no local state, so a zombie is any worker acting  *)
(* after its lease expired or its custody was superseded — the model's     *)
(* adversary is unconstrained worker behavior with the store as the sole  *)
(* arbiter. The receipt's content is deterministic given the job, so       *)
(* receipt stability and zombie harmlessness reduce to state invariants    *)
(* over one fixed record. Stability itself (receipt and outputs are never  *)
(* cleared or rewritten) is structural: no action does either.             *)
(***************************************************************************)

CONSTANTS W,            \* workers
          MaxGen,       \* generation bound
          Dur,          \* lease duration in ticks
          TimeMax       \* clock bound

VARIABLES claims,    \* set of claim records
          outputs,   \* BOOLEAN: the deterministic output object exists
          receipt,   \* BOOLEAN: the receipt record exists
          dead,      \* BOOLEAN: the dead record exists
          floor      \* shared store-time floor

ClaimRec == [ gen: 1..MaxGen,
              worker: W,
              attempt: 1..MaxGen,
              cont: BOOLEAN,
              time: 0..TimeMax ]

Vars == <<claims, outputs, receipt, dead, floor>>

TailOf == CHOOSE r \in claims : \A s \in claims : s.gen <= r.gen
HasTail == claims # {}

Init == /\ claims = {}
        /\ outputs = FALSE
        /\ receipt = FALSE
        /\ dead = FALSE
        /\ floor = 0

Tick == /\ floor < TimeMax
        /\ floor' = floor + 1
        /\ UNCHANGED <<claims, outputs, receipt, dead>>

(*************************************************************************)
(* Claims: first claim, takeover after expiry, renewal by the holder.    *)
(* Same structural put-if-absent encoding as the claims model: an        *)
(* action writes a generation above the current tail, so no contender   *)
(* writes the same generation twice.                                     *)
(*************************************************************************)
FirstClaim ==
    /\ ~HasTail /\ ~receipt /\ ~dead
    /\ \E w \in W :
         claims' = claims \union { [gen |-> 1, worker |-> w, attempt |-> 1,
                                    cont |-> FALSE, time |-> floor] }
    /\ UNCHANGED <<outputs, receipt, dead, floor>>

TakeOver ==
    /\ HasTail
    /\ ~receipt /\ ~dead
    /\ LET tail == TailOf
       IN  /\ tail.gen < MaxGen
           /\ floor >= tail.time + Dur
           /\ \E w \in W :
                claims' = claims \union { [gen |-> tail.gen + 1, worker |-> w,
                                           attempt |-> tail.attempt + 1,
                                           cont |-> FALSE, time |-> floor] }
    /\ UNCHANGED <<outputs, receipt, dead, floor>>

Renew(w) ==
    /\ HasTail
    /\ ~receipt /\ ~dead
    /\ LET tail == TailOf
       IN  /\ tail.gen < MaxGen
           /\ tail.worker = w
           /\ claims' = claims \union { [gen |-> tail.gen + 1, worker |-> w,
                                          attempt |-> tail.attempt,
                                          cont |-> TRUE, time |-> floor] }
    /\ UNCHANGED <<outputs, receipt, dead, floor>>

(*************************************************************************)
(* The commit rule: outputs are written put-if-absent at a deterministic *)
(* key BEFORE the receipt. Content is deterministic, so any writer —     *)
(* including a zombie — can only commit the identical first-wins bytes.  *)
(*************************************************************************)
WriteOutput ==
    /\ HasTail                  \* the claim holder writes outputs
    /\ ~dead
    /\ outputs' = TRUE
    /\ UNCHANGED <<claims, receipt, dead, floor>>

(*************************************************************************)
(* Acknowledgment: requires the outputs (commit rule) and refuses when   *)
(* dead terminalized first. Any worker may ack — a zombie's receipt      *)
(* write hits the same key with the same deterministic evidence, so it   *)
(* wins only if first, and is a no-op (stutter) when the receipt already *)
(* exists: idempotent re-ack, non-destructive.                           *)
(*************************************************************************)
Ack ==
    /\ HasTail                  \* ack requires custody (zombies included)
    /\ ~dead
    /\ outputs
    /\ receipt' = TRUE
    /\ UNCHANGED <<claims, outputs, dead, floor>>

(*************************************************************************)
(* Bury: refuses when a receipt terminalized the job first — the         *)
(* terminal-record mutual exclusion, both directions.                    *)
(*************************************************************************)
Bury ==
    /\ ~receipt
    /\ dead' = TRUE
    /\ UNCHANGED <<claims, outputs, receipt, floor>>

Next == Tick \/ FirstClaim \/ TakeOver \/ \E w \in W : Renew(w)
        \/ WriteOutput \/ Ack \/ Bury

Spec == Init /\ [][Next]_Vars

(*************************************************************************)
(* Invariants (state predicates; stability properties are structural     *)
(* and documented at the actions: no action clears or rewrites a         *)
(* receipt or an output).                                                *)
(***************************************************************************)

TypeOK ==
    /\ claims \subseteq ClaimRec
    /\ outputs \in BOOLEAN
    /\ receipt \in BOOLEAN
    /\ dead \in BOOLEAN
    /\ floor \in 0..TimeMax

\* At most one terminal record per job.
AtMostOneTerminalRecord == ~(receipt /\ dead)

\* The commit rule's visibility half: a receipt implies its outputs
\* exist.
OutputsPrecedeReceipt == receipt => outputs

\* Claims never outlive terminalization.
ClaimsBoundedByTerminal == receipt => HasTail

=============================================================================

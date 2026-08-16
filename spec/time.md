# StowQ/1 Time

Normative.

## Store-time oracle

When a participant needs "now" for a protocol decision (expiry evaluation,
admissibility basis, bucket computation), it establishes a **wall floor**:
PUT `meta/clock/<nonce>` (tiny body), read it back through the profile's
declared timestamp surface, and take the store-assigned timestamp. The floor
is a proven lower bound on store time — the store said so about an object
the participant just created. Beacons carry no protocol state. Participants
MAY reuse a floor for a configured staleness window; floors are lower
bounds, so staleness only delays work, never delivers early.

A floor MAY be raised to the stored watermark bucket
(`max(floor, bucket × width)`): the bucket was derived from an earlier
proven floor, so it is a proven lower bound on store time, and the max
of two lower bounds is a lower bound. Regression detection compares
the fresh beacon before any raise, so raising never masks a
regression; the raise is bounded by the skew guard.

## Expiry semantics

A lease is expired when `floor ≥ claim_store_time + lease_duration_ns +
skew_guard`, with `skew_guard` a per-profile constant absorbing the store's
internal clock dispersion. Normative profile constraints: `skew_guard ≥ G`,
`lease_duration ≥ G + skew_guard`, and all bucket widths `≥ G`. Sub-second
leases are out of profile on every currently listed store. Because both
operands come from the same clock authority, participant clock skew is
irrelevant.

## Watermark

`meta/watermark` is a CAS'd record `{ highest_observed_wall_bucket,
sequence, record_digest }` — the only mutable object in the protocol.
Participants advance it monotonically (If-Match CAS; a lost race means
someone advanced it further — re-read and proceed). Wall-sensitive
operations — delayed-job promotion and expiry-based takeover — MUST fail
closed if no floor at or above the relevant bucket can be established. This
prevents early delivery under a clock rollback: a store or profile
misreporting timestamps backward is detected as a watermark regression and
quarantine-flagged (`0x0012`) rather than acted on.

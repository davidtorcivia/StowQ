# StowQ/1 Reason Registries

Normative. Corruption is never mixed with dead-letter policy.

## Dead Reasons

| Code | Name |
| ------ | ------ |
| 0x0000 | unspecified |
| 0x0001 | consumer_rejected |
| 0x0002 | unsupported_content_type |
| 0x0003 | administrative_bury |
| 0x0004 | attempts_exhausted |
| 0x0100-0x7fff | application-defined |
| 0x8000-0xffff | private use |

## Quarantine Reasons

| Code | Name |
| ------ | ------ |
| 0x0001 | envelope_corrupt |
| 0x0002 | payload_corrupt |
| 0x0003 | key_parse_failed |
| 0x0004 | key_tag_failed |
| 0x0005 | key_record_mismatch |
| 0x0006 | unsupported_required_feature |
| 0x0007 | duplicate_state_conflict |
| 0x0010 | inadmissible_claim |
| 0x0011 | output_digest_conflict |
| 0x0012 | store_time_regression |
| 0x0013 | receipt_evidence_mismatch |
| 0x0014 | orphan_referenced_payload_missing |
| 0x0100-0xffff | implementation/private detail |

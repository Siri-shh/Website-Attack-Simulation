# M2 independent audit and integration review

Reviewer: gpt-6.1-sol, high reasoning. Result: **PASS**. No material findings block the M2 checkpoint or T06.

## Scope and evidence

Read AGENTS.md, RESUME, PROGRESS, D19, the approved specification/plan and T05 brief, audit.py, test_audit.py, shared config/crypto/database/schema contracts, T05 report, and the prior T03/T04 independent PASS reports. T03/T04 were considered only for integration and unresolved concerns; their completed reviews were not repeated. The controller supplied current Git status before this report was written: only expected M2 code/tests/conftest and durable documentation changed; this report was absent. Only this report was written. The reviewer ran no shell, Git, tests, installations, services or helpers and edited no product files.

Controller-supplied execution evidence:

- Audit red: **72 intended stub failures in 10.37s**, without collection errors.
- Audit green: **72 passed in 10.14s**.
- Full available suite: **168 passed in 21.61s**, exit 0, using .venv/Scripts/python.exe -m pytest -q --tb=short.

These are controller results, not independently executed reviewer results.

## Reviewed audit behavior

- audit.py:18-50 enforces the exact eleven-field payload, live domain, lowercase 32-character UUID hex, integer timestamp excluding bool, approved application kinds, nullable string context, string outcome, and nullable TCP port in 1..65535. Extra form/content/password/cookie/key fields are rejected before signing; validation messages contain no submitted values.
- audit.py:52-66 uses the shared IP normalizer for actual peer/destination literals, converts unavailable or invalid source values to unknown, rejects invalid destinations, and validates into a fresh dictionary without mutating the caller's payload. The same normalized values are both signed and indexed.
- audit.py:69-88 signs shared canonical UTF-8 JSON directly with the persistent Ed25519 key and inserts every approved indexed field from that same dictionary using bound parameters. Existing (domain,event_id) evidence returns unchanged before signing; even a valid differing replay cannot replace it. The database conflict clause is limited to the same uniqueness constraint. No commit, rollback, or explicit transaction is hidden in the function; rollback and visibility tests confirm the caller retains transaction ownership.
- audit.py:91-121 rejects malformed or noncanonical stored JSON, genuinely signed but invalid/unnormalized payloads, missing indexed/evidence fields, and any indexed type/value disagreement. Signature decoding requires canonical padded Base64 and exactly 64 bytes; the persisted public key verifies the exact canonical payload. Expected parser, format and signature failures return False without changing or resigning evidence.
- Tests use real SQLite rows and genuine Ed25519 signatures with an independent JSON serialization oracle. They cover all application kinds, nullable context, Unicode, normalization, immutable input, altered signed/indexed fields, wrong keys, malformed evidence, duplicate no-op without access to signing, prohibited extra fields, and caller rollback/visibility.

## Integration boundaries retained

The audit consumer correctly shares T03's persisted signing identity and T04's canonical serialization. Neither consumer replaces keys or changes record timing observations. There are no unresolved T03/T04 findings requiring a fix at M2. Existing accepted boundaries remain: TLS certificate/key replacement is two atomic operations and startup detects an incomplete pair; record duration/byte observations are outside the approved authenticated envelope. T16 must retain serialized initialization and explicit certificate-only renewal as recorded in T03-review.md.

T10 remains responsible for evaluating only newly inserted application events in the caller's transaction, excluding invalid signed evidence from rule inputs, and displaying invalid evidence explicitly during inspection. Subsequent authentication/service tasks must continue supplying opaque session_ref rather than cookie values and actual peer addresses rather than forwarding headers. These are frozen downstream contracts, not missing T05 implementation.

## Next action

Controller updates T05 and M2 durable green/review records and plan checkboxes, runs the planned diff/staging checks, and creates the M2 milestone commit and checkpoint/m2-crypto tag. T05.md still records green/review as pending and must be reconciled with the supplied results and this PASS before checkpointing.

# Implementation decisions

These decisions travel with the repository and override conflicting worker assumptions.

| ID | Decision | Reason |
| --- | --- | --- |
| D01 | Independent storage and admin Flask apps/listeners; ports 8443 and 8444 | User requires a separate admin website, not a storage route |
| D02 | Docker server 172.29.0.20 and client 172.29.0.10 on 172.29.0.0/24; configurable physical LAN fallback | Two devices, without reusing the old running project's subnet |
| D03 | Storage always enforces authorization; no scenario/vulnerable/attack controls | User's clarified scope |
| D04 | External attacker helpers are optional independent clients, not a framework service or detector input | User's clarified script purpose |
| D05 | Owner's storage page shows full ciphertext, SHA-256 hash, Ed25519 signature, nonce, timestamps and measured generation durations | Latest user requirement supersedes the earlier omission of storage evidence |
| D06 | SHA-256 is labelled a hash; Ed25519 signs canonical encrypted envelope bytes | SHA-256 alone is not a digital signature |
| D07 | Time only AES-GCM encrypt, SHA-256 digest, and Ed25519 sign calls with perf_counter_ns; keep latest version metrics | Actual per-operation generation measurements; no invented speed comparisons or benchmark loops |
| D08 | Use SQL-backed event windows evaluated atomically during insertion; no volatile rule engine, outbox, cursor, or watermark subsystem | Restart persistence with fewer components |
| D09 | R1/R2 emit on threshold crossing within the active window, not fixed cooldown | Matches the approved spec; a suggested fixed-cooldown design was rejected |
| D10 | Sign application events with Ed25519, not HMAC; retain deterministic offline:<file SHA-256> domains | Matches digital signature requirement and prevents duplicate offline replays; suggested HMAC/random scopes were rejected |
| D11 | Console polls every 2000 ms; IP blocks are manual and apply to storage admission, not OS firewall | Approved behavior |
| D12 | Luna edits mechanical tasks only; Sol resolves thinking/complex work; controller runs all shell/tests/Git | Explicit user delegation requirements |
| D13 | Durable tracked ledger/reports survive completion and account changes; checkpoint tags mark milestone commits | Explicit resumability/version-history requirements override deletion of scratch ledgers |
| D14 | Work in the user's requested new_project checkout on feature/storage-security; no additional worktree needed | New dedicated directory already isolates this project from the old Project directory |
| D15 | Latest encrypted record only; no old ciphertext versions, revision browser, signup, or repeated benchmark suite | Keep the approved storage scope small |
| D16 | Include templates/*.html as well as templates/**/*.html in package data; ignore generated *.egg-info/ | Ensure the shared root login template is packaged and editable-install metadata stays out of history |
| D17 | Keep Windows TShark fallback; simulate missing PATH and fallback in the absent-tool test; require explicit NOT NULL even on SQLite text primary keys | Sol diagnosed the environment-specific test failure and schema NULL semantics during T01 |

Append later entries with task ID, decision, reason, and effect on the contracts. Resolve ambiguities using the user requirements and spec before changing the plan.

D18 (T03 Sol contract): ensure_certificate(config, *, renew=False) supports explicit certificate-only renewal; never replace data/signing/session keys during renewal. Missing/corrupt required keys raise RuntimeError naming the file; SAN mismatch directs init --renew-certificate. KeyRing hides secret fields from repr. Existing records or any events prevent missing-key regeneration.

D19 (T05 Sol validation): signed application payloads require the exact approved field set, live domain, lowercase UUID hex event_id, integer timestamp (excluding bool), known application kind, nullable string context and nullable valid TCP port. Normalize actual valid peer/destination IP literals; unknown/invalid source becomes unknown. Indexed values must equal the canonical signed payload; verification rejects noncanonical payloads. Duplicate (domain,event_id) insertion is a no-op preserving original evidence even if the submitted replay differs.

D20 (T07 Sol ruling): successful storage/admin logins sign the fresh session_ref; authenticated blocked requests retain the current username/reference; anonymous blocks have null context. Credential/role failures clear identity and sign attempted canonical username with null reference. Logout enforces CSRF, signs departing username/reference before clearing, then redirects303; rejected CSRF preserves identity and adds no outcome event. Destination uses actual app configured port, record_id=null. See reports/T07-contract.md for fixed Luna test edits; these correct two null-session test expectations and add bounded required logout coverage.

D21 (T07 Sol diagnosis): logout requests without peer overrides correctly log127.0.0.1; correct the test helper expectation. CSRF rejects missing/empty/non-ASCII submitted or stored string tokens with400 before compare_digest. Blocked-request account context requires role=user and both nonempty string username/session_ref; otherwise both are null. Add bounded regressions before these fixes; see T07-contract.md.

D22 (T08 mechanical integration): storage factory registers Jinja filter utc=existing config.format_utc so T09 renders stored integer microsecond timestamps as UTC without changing service rows. Auth flashes Login successful; storage base renders escaped flashed messages, fulfilling the requested successful-login display.

D23 (M3 Sol review): T08 error context adds message alongside existing error. T09 UI wording Digital signature verification passed is accurate; match test expectation to that text. Consume and assert Login successful on the ordinary landing GET before comparing two subsequent detail HTML refreshes; retain exact cryptographic evidence/timings and no-regeneration checks. No product UI change needed for these two failures. See M3-review.md.

D24 (T10 Sol rule boundary): evaluate_event has no Config and packet payload has no SYN flags. T13 parser enforces incoming SYN without ACK to configured server before producing unsigned connection_attempt/observed events. R1 evaluates those parser-filtered captured observations grouped by domain/source/destination, avoiding aggregation across destinations. Keep existing APIs; do not duplicate capture configuration into rule engine.

D25 (T10 Sol historical evidence): R4 requires a verified signed foreign_record_denied event with nonempty username/session_ref/record_id and matching outcome; the record service attests the existing foreign record denial after its ownership/existence check. Rules do not requery current records/users/login history to validate historical denial evidence, because later state changes must not erase past facts. Unauthenticated/invalid-context or other outcomes do not qualify.

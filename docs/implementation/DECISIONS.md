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

D26 (M4 Sol scoped review): T12 UI tests own their local config/keys-seeded real console fixture; do not borrow the module-local T11 fixture or refactor conftest. Seed the block only in the block-form test before asserting Unblock. Remove the unused broken T11 _record_block_event helper in a bounded mechanical cleanup; working block routes remain intact. See M4-review.md. This avoids broad rewrites and preserves empty-state coverage.

D27 (M4 Sol polling fix): capture requestedDomain before fetch; after awaited JSON, render only while it equals the current selection. In finally clear inFlight, then immediately refresh if selection changed, keeping requests serialized. Verify the actual unmodified console.js through one dependency-free Node VM/test delayed-response regression. Node is a controller development-check tool only; no application/Docker runtime dependency is added.

D28 (T13 Sol diagnosis): the IPv6 test still passed the IPv4 default server while its packet destination was IPv6. Set that test server=2001:db8::20; retain strict configured-destination parser filtering. This is a fixture correction, not a production change.

## D29 — Capture lifecycle injection and status

Sol design: CaptureWorker accepts optional process_factory and clock for deterministic lifecycle checks; export TSHARK_FIELDS for offline reuse. Concurrent stdout/stderr readers and an exit supervisor prevent pipe deadlock. Informational stderr alone does not degrade capture; bounded stderr informs actual exit errors. Missing interface/start failure is degraded, idle silence remains running. Stop terminates, waits with kill fallback, joins owned threads and retains the capture. No new start while owned resources remain. Health persists the five console allowlisted fields under capture.

## D30 — Offline import result and validation

Sol specifies alert_count as newly added alerts during this import: first five-port replay returns 1, duplicate import 0 while retaining its existing offline alert. analyze_pcap accepts injected process_runner (default subprocess.run), streams file SHA256, fully decodes/validates and sorts accepted fields before database insertion. PcapAnalysisError reports file, decoder and row errors. Offline replay never changes live capture status or blocks.

## D31 — Launcher seeding and reset ownership

Sol specifies fixed-ID missing seed records via seal_record and direct transactional INSERT because save_record non-null IDs are edits. Preserve existing users and records. Serve and reset exclusively claim the same atomic server.pid marker before initialization/mutation; refuse existing markers with inspection guidance. Reset only allowlisted database/sidecars and captures after full resolved containment and symlink/reparse preflight, preserving keys and unknown files; reject repository/root/ancestor data targets. Stop only owned capture/listeners; shutdown only started live serve loops, close owned bindings. Preserve marker when cleanup is incomplete. Current Werkzeug official docs/source checked for threaded TLS make_server lifecycle; Context7 incomplete specifics documented in T16 report.

D31 reset safety detail: reject checkout .git/security_lab/tests/docs and read-only sibling Project subtrees; allow dedicated data dirs only with allowlisted deletion. Preflight every capture subentry using symlink/lstat Windows reparse checks before any removal. Existing malformed markers also require refusal; never kill a recorded PID or automatically remove a stale marker.

## D32 — Graceful Docker SIGTERM shutdown

Independent Sol review found serve handled KeyboardInterrupt but not Docker stop SIGTERM, risking leftover persistent server.pid and failed restart. Install and restore a SIGTERM handler during main-thread serve lifetime that enters the same owned-resource cleanup. Add deterministic handler-path regression and verify actual Docker stop/restart at T20. This is a launcher fix, not a process/PID cleanup bypass.

## D33 — Client container stays available with finite sleeps

Independent Sol review and controller Python reproduction confirmed time.sleep(float('inf')) raises OverflowError rather than keeping the client alive. Prescribed Luna correction is a while True loop with time.sleep(3600), represented with actual Python newlines inside the JSON CMD. Keep client independent; actual container liveness verified at T20.

## D34 — Bridge network for localhost publication

Actual Docker deployment: Internal=true network produced empty published port arrays and host HTTPS connection refusal despite healthy server and running capture. Sol checked current Docker official docs: use the normal user-defined bridge by removing only internal:true, preserving subnet172.29.0/24, static .10/.20, eth0 and loopback-only published ports. Recreate only this Compose project without volumes/reset; preserve data. Bridge permits outbound traffic; host ingress remains localhost-only. Do not claim a Docker29-specific regression without supporting release evidence. Controller real SIGTERM stop succeeded, server.pid removed and PCAP retained.

## D35 — Real TShark Boolean field compatibility

Root TShark4.4.19 actual PCAP emits True/False for SYN/ACK; numeric-only parsing rejects valid connections. Sol fixed contract: flag accepts exact 1/True and 0/False tokens, rejects every other present token; apply SYN, ACK and nonempty retransmission, empty retransmission remains False. Preserve all incoming server/SYN-without-ACK scope, missing fields and dedup semantics. Luna performs predetermined correction after regression red; root reruns packet/capture/pcap then rebuilds and verifies real harmless client observation before probing.

## D36 — Smoke restart evidence and browser artifacts

Sol test-only Docker smoke adds --state (default /tmp/storage-smoke-evidence.json), --retain-block and --verify-restart. Standard smoke demonstrates unblock then optionally deliberately re-blocks its observed client IP, saving only public record crypto/timing/timestamps and event/alert IDs. After controller stop/read/import/restart, verification proves retained block/evidence, then admin unblocks and normal login resumes. No server lifecycle commands in the client test. Browser QA uses Playwright CLI fallback after in-app browser initialization failed; isolated QA context accepts lab self-signed certificate, while actual host/client HTTPS was independently CA-verified. Generated browser outputs stay untracked.

## D37 — Storage-only record cryptographic evidence

Fresh Sol review reconciled stale spec text against latest explicit user steering (crypto values/timings in storage website itself, separate admin log-monitor console, do not overbuild) and approved T11/T12 snapshot contract. Record ciphertext/hash/signature/timings remain owner-protected on storage. Console presents signed audit and network evidence, not an additional encrypted-record metadata surface. Update stale specification sentence accordingly; no new admin record endpoint/table.

## D38 — Preserve application logs under packet traffic

Actual browser polling creates network observations; mixed newest100 events eventually showed100 network/0 application events despite persisted signed logs. Fresh Sol specifies independent per-domain newest100 application and newest100 connection_attempt quotas, combined deterministically sorted(time_us,seq)descending in existing events key (up to200), existing signature_valid allowlist unchanged. Add regression packet flood cannot evict signed logs, bothbounds100, domainisolation and signatures intact. Bound table-wrap height with overflow:auto so allrowsremaininspectable andalerts/blockcontrolsreachable. No filtering out admin traffic, no detector or schema changes.

## D39 â€” Preserve encrypted record versions for demonstration

The user approved owner-only history so a professor can compare cryptographic evidence after text edits. Keep the current `records` row as the latest version and add encrypted/signature-verified snapshots keyed by record and version. Backfill pre-feature records exactly once with a durable migration marker; never silently repair a missing snapshot during every startup. Snapshot both normal saves and direct seed-account records atomically. Owner-check before loading all versions in one consistent read transaction, verify every version before returning any plaintext, and require latest snapshot equality with the current row. Retain timings/byte counts as measurements outside the signed envelope. No restore/delete controls, hash chain, deletion detector, retention controls, or new dependencies. GPT-6.1 Sol design review approved this scope.


## D40 ? Isolated administrator cryptography analysis lab (T22)

The user approved a separate Analysis page in the existing admin console with four panels: AES encrypt/decrypt, explicit SHA-256 preimage/second-preimage/collision analyses, AES confusion/diffusion/avalanche, and Safe tamper. Safe tamper uses a disposable fake sample and changes only a copy; it must show rejection without reading or changing Bob/Alice records. Admin-selected text and results stay in memory only, are never persisted/logged/audited, and are capped at 10 KB. All actions use admin auth and CSRF. Do not change storage behavior, schema, or dependencies. Use complete SHA-256 output (256 bits), not a truncated digest, and repeated AES-GCM timings (warm-up + 1,000 encrypt/decrypt samples, unique nonce per encryption; median/p95). GPT-6.1 Sol finalized the detailed empirical workloads and claim wording in D41 before the spec.


## D41 ? T22 crypto-analysis measurement contract

GPT-6.1 Sol design review approved the empirical boundaries and corrected the claims. Use full 32-byte SHA-256 digest comparisons, with up to 10,000 candidate trials for each of preimage, second-preimage, and collision search; show attempts and total elapsed search time, and call a no-match result expected bounded evidence, never proof. Explain generic work estimates of about 2^256 for preimage/second-preimage and 2^128 for collision. AES-GCM analysis performs 20 warm-up pairs and 1,000 timed encryptions plus corresponding decryptions per action; generate 1,020 unique 12-byte nonces from a fresh random 4-byte prefix and 8-byte counter. Report median and nearest-rank p95. For AES primitive analysis, run 32 independent random 256-bit keys against the selected 16-byte block, flip each 128 plaintext bit and each 256 key bit, yielding 4,096 plaintext and 8,192 key comparisons plus 32 baselines. Label plaintext changes diffusion illustrations, key changes confusion/key-sensitivity illustrations, and aggregate/output-bit results as finite empirical avalanche evidence, not proof/pass-fail. ECB may be used only for isolated single-block primitive analysis and must be called unsuitable for message protection. Safe tamper seals a transient synthetic envelope with fresh AES/Ed25519 keys, confirms it opens, flips a ciphertext bit in a copy, then confirms production verification rejects it; do not claim the GCM tag was the rejecting layer because hash/signature checks occur first. All values remain transient and no DB, production keyring, or audit access is allowed.


D42 ? T22 scope narrowed by user: Safe tamper is on hold and is excluded from M9. The active Analysis page has only three panels: AES-GCM timing/evidence, full SHA-256 property analysis, and AES confusion/diffusion/avalanche. Retain D40/D41 as historical design notes; their Safe tamper details are deferred and are not implementation requirements.


D43 ? T23 analysis result contract: use Sol?s nested result dictionaries in the T23 plan update, preserving raw nanoseconds and unrounded statistics. `candidate_limit` must be an integer in [1, 10000], explicitly rejecting bool and out-of-range values; each hash-property budget is independent. Inject private `_digest`, `_random_bytes`, and `_now_ns` seams so tests can prove full-digest success/collision/exhaustion deterministically without expensive searches. AES-primitive bit index 0 is the MSB of byte 0; SAC matrix rows are plaintext input bits and columns ciphertext output bits.


D44 ? T23 Sol implementation review PASS. Preimage search counts candidate hashes, skips a source-identical generated candidate without consuming budget, and advances its counter; bounded work remains <= candidate limit hashes. Deterministic tests cover success paths and exact AES operation counts/timing indices. In the UI describe the SAC matrix as output-bit flip frequencies across 32 random keys for one selected input block; this is limited empirical evidence and not a security verdict.


D45 ? T24 analysis page review PASS. Existing `require_login("admin")` redirects unauthorized roles to the console login; T24 tests assert that established behavior. All three analysis POSTs enforce CSRF and byte limits, set no-store, avoid database/audit/keyring calls, and display escaped transient inputs/results. Sol reviewed route and presentation scope and found no material fixes. M9 passed 344 tests with 1 skip.

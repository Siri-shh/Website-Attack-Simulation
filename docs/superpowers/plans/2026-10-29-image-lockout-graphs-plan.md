# Image Records, R2 Restriction, and Crypto Graphs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Repository `AGENTS.md` overrides generic worker routing: the controller runs every command, test, process, dependency install, and Git operation; one implementation writer at a time.

**Goal:** Finish the classroom checklist with owner-only encrypted image records, a 90-second response to live R2 alerts, measured crypto graphs, and a clearer login page.

**Architecture:** Extend the existing Flask/SQLite applications and immutable record versions. New records use a v2 signed envelope that binds separate AES-GCM image ciphertext; old v1 evidence remains verifiable. Derive the R2 cooldown from persisted live alerts inside the login decision transaction; render charts from saved record measurements and isolated in-memory admin experiments.

**Tech Stack:** Python 3.13 Docker / >=3.11 local, Flask 3.1, SQLite, cryptography 50, Pillow 12.3, pytest, existing HTML/CSS/JavaScript. No charting library or new service.

**Spec:** `docs/superpowers/specs/2026-10-28-image-lockout-graphs-design.md`

## Global Constraints

- Build only in this `new_project` checkout. Preserve ignored runtime `data/`, keys, captures, database, and the unrelated untracked startup-recovery report. Never edit sibling `Project`.
- Keep storage and admin websites separate. Preserve R1/R3/R4/R5, manual IP blocks, and R3's 120-second R2-to-success window. Safe tamper remains deferred.
- One PNG/JPEG image per record, maximum 1,048,576 bytes and at most 16,000,000 decoded pixels; old versions retain their original image evidence. Use only verified owner reads to reveal an image or its ciphertext.
- Storage sign-in restriction is exactly 90,000,000 microseconds from a live R2 alert for the normalized source IP and username. Existing sessions and admin sign-in remain unaffected. Restricted submissions are signed separately and never count as credential failures.
- Existing saved text timing fields retain their meanings. New image timing fields are separate. Record read timings are transient, not backfilled or saved. UTC microseconds remain canonical; display IST.
- Admin analysis remains CSRF-protected, no-store, in-memory, isolated from production records/keys/audit, and retains the existing 10,240-byte text-input limit, full 256-bit SHA searches, 1,000-sample AES experiment, and 32-key AES primitive experiment.
- Do not promise 100% character difference or call bounded SHA no-match proof of resistance. Single-block ECB is an analysis primitive only; storage uses AES-256-GCM.
- User authorized `gpt-6-sol`/high as the available substitute for unavailable `gpt-6.1-sol`; use it for algorithms, architecture, debugging, and independent reviews. Use `gpt-6-luna`/medium only for fixed mechanical work. Always set `fork_turns: none`, model, and effort. Workers edit assigned files only; controller supplies command results and writes durable reports.
- Before each task, inspect status and ledger; set `IN_PROGRESS` with phase/base commit/owned files. Update this plan, `PROGRESS.md`, `DECISIONS.md`, and the task report after checks and review. Never mark a task complete from agent claims alone. Preserve every committed report and checkpoint tag.

## Review Focus

- Existing databases already contain signed v1 current rows and snapshots: migration must leave their byte-for-byte evidence unchanged and still verify (T29 test).
- A malformed, truncated, oversized, or decompression-bomb image must not create a record, snapshot, or success audit event (T29/T30 tests).
- Simultaneous fifth and sixth login attempts must serialize: the sixth cannot bypass an R2 created by the fifth, even with a correct password (T27 test).
- A corrupt historical image must make the entire owner history read fail without partial plaintext, while foreign users cannot retrieve preview or ciphertext (T30 test).
- Browser/admin graphs must use actual numeric inputs and correct units; one-point histories, no-match SHA searches, and transient analysis inputs must be labelled honestly (T32/T33 tests).

## File map and task boundaries

- `security_lab/auth.py`, `audit.py`: atomic R2 sign-in gate and signed restricted event (T27).
- `security_lab/console.py`, `templates/console/dashboard.html`, `static/console.js`, `templates/login.html`, `static/login.css`: cooldown display and shared login design (T28); later isolated analysis route (T32).
- `security_lab/schema.sql`, `db.py`, `crypto.py`, new `images.py`, `pyproject.toml`, `requirements-lock.txt`: v2 envelope, migration, image validation/crypto (T29).
- `security_lab/records.py`, `storage.py`: versioned image service and owner-only routes (T30).
- `templates/storage/form.html`, `detail.html`, `static/storage.css`, new `static/record-evidence.js`: image upload, preview, lazy ciphertext (T31); record charts (T33).
- `security_lab/analysis.py`: bounded size sweep, Ed25519 timings, character-change result, graph data (T32).
- `docs/DEMO.md`, `README.md`, `docs/CODE_GUIDE.md`, reports and ledgers: demonstration and recovery instructions (T34).
- Tests extend `tests/test_auth.py`, `test_console.py`, `test_console_ui.py`, `test_crypto.py`, `test_db.py`, `test_records.py`, `test_storage_ui.py`, and `test_analysis.py`; add `tests/test_images.py` for isolated validation (owning tasks below).

## M10 — R2 response and login

### Task T27: Atomic storage sign-in restriction

**Worker:** `gpt-6-sol`, `high`, `fork_turns: none`; complex auth transaction. Report: `docs/implementation/reports/T27.md`.

**Files:** Modify `security_lab/auth.py`, `security_lab/audit.py`, `tests/test_auth.py`, and only if necessary `tests/test_rules.py`. Do not alter rule windows.

**Interfaces:** Add `restriction_expiry_us(conn, *, src_ip: str, username: str, now_us: int) -> int | None` in `auth.py`, querying the newest matching `domain='live' AND rule='R2'` alert; return expiry only while `now_us < alert.time_us + 90_000_000`. Add audit kind/outcome `login_restricted_attempt` to the signed allowlist. Refactor login event insertion to accept the active connection. Login template context provides `login_service` (`storage` or `admin`), `login_error: str | None`, and `restriction_seconds: int | None`; restricted POST is 429 with ceiling-second `Retry-After`, ordinary fifth bad credential remains 401. Set the session only after the decision transaction commits.

- [x] **Step 1 — tests:** Add `test_r2_restricts_only_matching_ip_username_for_exact_90_seconds` asserting fifth failure 401/R2, same-pair correct password 429 with `Retry-After`, other pair unaffected, exact expiry success, and restricted attempts signed without another R2. Add `test_concurrent_fifth_and_sixth_login_serializes` with controlled transaction ordering; assert no successful bypass. Add manual-block precedence, existing-session, admin/offline isolation, and R3 90–120-second regression assertions.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_auth.py tests/test_rules.py -q`; record the expected new-test failures in T27 report.
- [x] **Step 3 — implementation:** Keep CSRF and trusted peer normalization. Verify password before lock if needed, then make the authoritative block/R2 lookup and signed outcome append inside one `BEGIN IMMEDIATE` transaction. Clear prior identity on restricted/failure responses; keep existing authenticated sessions on unrelated requests. Avoid nested `_record_event` transactions.
- [x] **Step 4 — green check (controller):** Repeat focused command; inspect signed events and `git diff --check`. Sol independently reviews the final auth diff and test evidence before T27 is COMPLETE.

### Task T28: Countdown, console expiry, and login presentation

**Worker:** `gpt-6-luna`, `medium`, `fork_turns: none`; interfaces frozen by T27. Report: `docs/implementation/reports/T28.md`.

**Files:** Modify `security_lab/console.py`, `security_lab/templates/console/dashboard.html`, `security_lab/static/console.js`, `security_lab/templates/login.html`, `security_lab/static/console.css`, `tests/test_console.py`, `tests/test_console_ui.py`, `tests/console_polling.test.cjs`; create `security_lab/static/login.css`.

**Interfaces:** For each live R2 alert in `snapshot`, add `restriction_expires_at_us`, `restriction_expires_at_ist`, and `restriction_remaining_seconds`; for offline or other rules these fields are null. `console.js` renders expiry from these fields on every 2-second refresh. The login template consumes T27's three context values; when restricted, show remaining seconds and preserve the 429 status. Keep CSRF fields and both service forms working.

- [x] **Step 1 — tests:** Add snapshot assertions for live R2 expiry/remaining and offline-null fields, template assertion for storage countdown and distinct console label, and Node polling assertion that the refreshed R2 expiry remains visible.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_console.py tests/test_console_ui.py -q` and `node --test tests/console_polling.test.cjs`; record new-test failures.
- [x] **Step 3 — implementation:** Add the three allowlisted fields, table cell and polling mapping. Use one centered login card (maximum 420 px), plain off-white background, a narrow existing-palette accent border (storage navy; console blue), two stacked labelled fields, visible focus ring, and inline error/countdown; no gradients, illustrations, icons, or attack-demo affordance. Escape user-controlled text through templates/`textContent`.
- [x] **Step 4 — green/milestone check (controller):** Repeat focused Python and Node commands; run `python -m pytest tests/test_auth.py tests/test_rules.py tests/test_console.py tests/test_console_ui.py -q`; obtain one Sol review of T28 UI plus M10 behavior. Update reports/ledger/checkboxes.

**M10 checkpoint commands (controller only, after all checks/review pass):**

```powershell
git diff --check
git add -- security_lab/auth.py security_lab/audit.py security_lab/console.py security_lab/templates/console/dashboard.html security_lab/templates/login.html security_lab/static/console.js security_lab/static/console.css security_lab/static/login.css tests/test_auth.py tests/test_rules.py tests/test_smoke.py tests/test_console.py tests/test_console_ui.py tests/console_polling.test.cjs docs/superpowers/plans/2026-10-29-image-lockout-graphs-plan.md docs/implementation/PROGRESS.md docs/implementation/DECISIONS.md docs/implementation/reports/T27.md docs/implementation/reports/T28.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: restrict R2 sign-ins and show cooldown"
git tag checkpoint/m10-r2-response
```

## M11 — Versioned encrypted images

### Task T29: Image validation, schema migration, and v2 cryptography

**Worker:** `gpt-6-sol`, `high`, `fork_turns: none`; cryptographic and migration algorithm. Report: `docs/implementation/reports/T29.md`.

**Files:** Modify `security_lab/schema.sql`, `security_lab/db.py`, `security_lab/crypto.py`, `pyproject.toml`, `requirements-lock.txt`, `tests/test_db.py`, `tests/test_crypto.py`; create `security_lab/images.py`, `tests/test_images.py`. Controller alone installs `Pillow==12.3.0` in the local environment before red/green checks and later rebuilds Docker.

**Interfaces:** Both record tables gain `envelope_schema INTEGER NOT NULL DEFAULT 1` plus nullable `image_nonce BLOB`, `image_ciphertext BLOB`, `image_mime TEXT`, `image_size INTEGER`, `image_plain_sha256 TEXT`, `image_cipher_sha256 TEXT`, `image_encrypt_ns INTEGER`, `image_hash_ns INTEGER`. All image columns are null or all populated. `validate_image_upload(raw: bytes, declared_mime: str) -> tuple[bytes, str]` in `images.py` returns original bytes and canonical `image/png` or `image/jpeg`, or raises `ValueError`; limit 1,048,576 bytes and 16,000,000 decoded pixels. Extend `seal_record(..., image_bytes: bytes | None = None, image_mime: str | None = None) -> dict` to create schema 2 envelopes by default. Keep `open_record(keys, row) -> dict[str, str]` and add `open_record_image(keys, row) -> tuple[str, bytes] | None` plus `open_record_measured(keys, row) -> tuple[dict[str, str], bytes | None, dict[str, int | None]]`. The measured dict keys are `hash_verification_ns`, `signature_verification_ns`, `text_decryption_ns`, `image_decryption_ns`; null image gives null image timing. v2 hash/signature binds a canonical image descriptor containing nonce, MIME, plaintext size/hash and ciphertext size/hash, not the 1 MiB BLOB. Preserve v1 envelope serialization byte-for-byte.

- [x] **Step 1 — tests:** Add fresh/old-DB idempotent migration and frozen-v1 evidence tests; image round trip, fresh nonce, all-null versus all-present fields, metadata/BLOB/tag tamper rejection, wrong owner/version AAD rejection, exact measurement scopes, and PNG/JPEG validation including truncated, spoofed, oversized, and bomb inputs. Assert v1 stored ciphertext/hash/signature never change.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_db.py tests/test_crypto.py tests/test_images.py -q`; capture expected new-test failures. Pillow installation is controller-only and its pinned version is recorded.
- [x] **Step 3 — implementation:** In one migration transaction add missing columns before old snapshot backfill; never rewrite legacy evidence. Validate images with Pillow decode (`verify()`, reopen, `load()`), treating decompression warnings as errors. Encrypt raw bytes with fresh AES-GCM nonce and canonical AAD binding purpose/id/owner/version/MIME/size; hash the plaintext and ciphertext; verify the v2 signed descriptor and both hashes on open before returning any text/image bytes. Keep v1 dispatch exact. Time actual crypto calls with `perf_counter_ns`.
- [x] **Step 4 — green/review (controller):** Repeat focused tests and `git diff --check`. Get independent Sol review of migration/envelope/AAD and test evidence before T30 consumes these interfaces.

### Task T30: Atomic image record service and owner-only endpoints

**Worker:** `gpt-6-sol`, `high`, `fork_turns: none`; version/auth integration. Report: `docs/implementation/reports/T30.md`.

**Files:** Modify `security_lab/records.py`, `security_lab/storage.py`, `tests/test_records.py`, `tests/test_storage_ui.py`.

**Interfaces:** Extend `_RECORD_FIELDS` with every T29 column. Extend `save_record(..., image_action: Literal['keep','replace','remove'] = 'keep', image_bytes: bytes | None = None, image_mime: str | None = None) -> dict`; replace alone requires bytes and canonical MIME; keep on an edit verifies/decrypts and re-encrypts image with fresh nonce for the new version. `record_image` GET at `/records/<record_id>/versions/<int:version>/image` returns verified raster bytes; `record_image_ciphertext` GET at the same path plus `-ciphertext` returns full Base64 text. Both routes are owner-only, no-store, `X-Content-Type-Options: nosniff`, and 404 for absent image/version. Raise existing `IntegrityError`/signed audit on corruption without partial response. Set storage upload limit to accommodate a 1 MiB multipart request; admin limit stays 65,536.

- [x] **Step 1 — tests:** Add create/keep/replace/remove history assertions (including fresh nonce on keep), current/snapshot equality, all-or-nothing corrupt historical image read, foreign-owner endpoint denial, no-image 404, preview MIME/no-store/nosniff, ciphertext Base64, malformed/oversize upload and rollback, and signed event behavior.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_records.py tests/test_storage_ui.py -q`; capture expected new-test failures.
- [x] **Step 3 — implementation:** Validate upload before transaction; use existing `BEGIN IMMEDIATE` save with one new snapshot and audit event. Authorize before any image bytes/evidence. Fetch requested historical version through verified history, not raw SQL bypass. Preserve old text API behavior and error mappings.
- [x] **Step 4 — green/review (controller):** Repeat focused tests; get Sol review of authorization, atomicity, and image evidence before UI work.

### Task T31: Image upload and evidence UI

**Worker:** `gpt-6-luna`, `medium`, `fork_turns: none`; fixed routes/fields from T30. Report: `docs/implementation/reports/T31.md`.

**Files:** Modify `security_lab/templates/storage/form.html`, `security_lab/templates/storage/detail.html`, `security_lab/static/storage.css`, `tests/test_storage_ui.py`; create `security_lab/static/record-evidence.js`. Minor `storage.py` template-context edits only if T30 left a documented requirement.

**Interfaces:** Form uses `enctype="multipart/form-data"`, input name `image`, action name `image_action`, accepted PNG/JPEG, and explicit keep/replace/remove controls on edit. Detail/history use T30 endpoint names and row image fields. A collapsed evidence control fetches full ciphertext only on expansion and inserts it with `textContent`; never embed a 1 MiB Base64 string in ordinary HTML. Text evidence and saved timings remain visible.

- [x] **Step 1 — tests:** Assert file control, edit actions, owner preview link, historical preview/evidence links, absence for text-only versions, escaped labels, lazy ciphertext behavior, and existing text evidence unchanged.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_storage_ui.py -q`; record new-test failures.
- [x] **Step 3 — implementation:** Add form/preview/evidence markup, small dependency-free JS, and existing-palette responsive CSS. Do not add a demo/tamper control.
- [x] **Step 4 — green/milestone check (controller):** Repeat focused tests, then `python -m pytest tests/test_db.py tests/test_crypto.py tests/test_images.py tests/test_records.py tests/test_storage_ui.py -q`; independent Sol review and report/ledger updates.

**M11 checkpoint commands (controller only, after all checks/review pass):**

```powershell
git diff --check
git add -- security_lab/schema.sql security_lab/db.py security_lab/crypto.py security_lab/images.py security_lab/records.py security_lab/storage.py security_lab/templates/storage/form.html security_lab/templates/storage/detail.html security_lab/static/storage.css security_lab/static/record-evidence.js pyproject.toml requirements-lock.txt tests/test_db.py tests/test_crypto.py tests/test_images.py tests/test_records.py tests/test_storage_ui.py docs/superpowers/plans/2026-10-29-image-lockout-graphs-plan.md docs/implementation/PROGRESS.md docs/implementation/DECISIONS.md docs/implementation/reports/T29.md docs/implementation/reports/T30.md docs/implementation/reports/T31.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: store verified encrypted images in record history"
git tag checkpoint/m11-image-records
```

## M12 — Crypto measurements, graphs, and final verification

### Task T32: Bounded size sweep and graph measurements

**Worker:** `gpt-6-sol`, `high`, `fork_turns: none`; measurement/algorithm contracts. Report: `docs/implementation/reports/T32.md`.

**Files:** Modify `security_lab/analysis.py`, `security_lab/console.py`, `tests/test_analysis.py`, `tests/test_console_ui.py`. Use T29's `open_record_measured` from storage detail without persisting read timings; `storage.py` and `tests/test_storage_ui.py` may be edited only for this call/contract.

**Interfaces:** Add `benchmark_size_sweep(*, sizes: tuple[int, ...] = (128, 1024, 10240, 102400, 1048576), samples: int = 100) -> dict` to isolated `analysis.py`. Return `sizes`, `samples_per_size`, and `points`; each point has `input_bytes` and nested `{median_ns,p95_ns,mib_per_s}` for `aes_encrypt`, `aes_decrypt`, `sha256`, `ed25519_sign`, `ed25519_verify`. Use ephemeral keys, synthetic buffers, unique AES nonces, fixed warm-up, and a bounded maximum workload (only the five approved sizes; 1..100 samples); reject invalid sizes/sample counts. Add an admin-only CSRF POST `/analysis/size-sweep` using no-store and no DB/audit/production keys. Extend `aes_primitive_analysis` result with `hex_character_change:{changed,total,percent}` using corresponding hex characters from two equal-length one-block AES outputs under one key and one controlled input change; preserve existing keys. Add `sac.summary_16x16`, each cell the mean of its corresponding 8x8 block in the existing 128x128 percentage matrix. Expose current read timing values in storage detail only, labelled separately from saved version timings.

- [x] **Step 1 — tests:** Deterministic clock/random seams prove median/p95/throughput units, 100 samples per size, no nonce reuse, correct encrypt/decrypt/sign/verify, max work rejection, complete isolation; assert character metric uses 32 hex characters and same-key bit change. Route test checks admin/CSRF/no-store and output. Storage test checks read timings are transient and saved row unchanged.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_analysis.py tests/test_console_ui.py tests/test_storage_ui.py -q`; record expected new-test failures.
- [x] **Step 3 — implementation:** Time only named crypto operations with monotonic nanoseconds; keep sample preparation out of timed spans. Do not alter the existing 1,000-sample AES/10,000-trial SHA/32-key primitive contracts. Use the T29 measured-open path for current record read observations.
- [x] **Step 4 — green/review (controller):** Repeat focused tests; independent Sol review of measurement meaning, bounds, nonce uniqueness and isolation before UI task.

### Task T33: Accessible graphs on records and Analysis

**Worker:** `gpt-6-luna`, `medium`, `fork_turns: none`; render only T29/T32 numeric contracts. Report: `docs/implementation/reports/T33.md`.

**Files:** Modify `security_lab/templates/storage/detail.html`, `security_lab/templates/console/analysis.html`, `security_lab/static/storage.css`, `security_lab/static/console.css`, `tests/test_storage_ui.py`, `tests/test_console_ui.py`; `security_lab/console.py` only for fixed result wiring from T32.

**Interfaces:** Use labelled HTML horizontal bar charts with adjacent numeric tables: each row labels its input size/version, and bar width is its duration divided by the largest duration in that chart; show the exact duration beside it. A separate bar group shows throughput in MiB/s. This requires no chart-coordinate algorithm. Size labels are bytes; time labels are ns or ms with explicit conversion. Record version series use text plaintext bytes for text AES, image size for image AES, envelope bytes for SHA/sign; current read measures are separately marked. Admin sweep plots five sizes and all five operations; SHA search plots attempts and elapsed time with no-match wording; AES primitive plots changed-bit percentages with a visible 50% reference, hex-character count/percentage, and T32's 16x16 SAC summary as color-coded cells while retaining the full matrix and ECB warning. A single point must not be described as a trend.

- [x] **Step 1 — tests:** Assert graph headings/axes/units, true saved version values, one-point label, all five admin size points/operations, SHA no-match caveat, AES 50% reference, character metric definition, and no input stored in markup outside the current response.
- [x] **Step 2 — red check (controller):** `python -m pytest tests/test_storage_ui.py tests/test_console_ui.py -q`; record new-test failures.
- [x] **Step 3 — implementation:** Add accessible charts and tables using numeric results only; sanitize template output and preserve responsive layout and existing evidence panels. No external chart library.
- [x] **Step 4 — green check (controller):** Repeat focused tests; inspect rendered HTML and browser pages at desktop/mobile sizes. Sol reviews final graph claims and UI evidence.

### Task T34: Demonstration guide and integration verification

**Worker:** `gpt-6-luna`, `medium`, `fork_turns: none` for bounded documentation only. Report: `docs/implementation/reports/T34.md`.

**Files:** Modify `docs/DEMO.md`, `README.md`, `docs/CODE_GUIDE.md`, `docs/implementation/PROGRESS.md`, `docs/implementation/DECISIONS.md`, and plan checkboxes. Controller owns final checks/commits/tags.

**Interfaces:** Explain one-image record create/edit/keep/replace/remove, owner preview and ciphertext, real timing versus synthetic size sweep, R2 fifth-failure/90-second wait/30-second R3 remainder, manual IP block distinction, AES/SHA/Ed25519 evidence, and where code lives. No unsafe/tamper demo additions.

- [x] **Step 1 — documentation:** Write concise professor walkthrough and code map; update ledger only with verified task outcomes supplied by controller.
- [x] **Step 2 — controller integration checks:** `python -m pytest -q`, `node --test tests/console_polling.test.cjs`, `docker compose config --quiet`, `docker compose build server`, `docker compose up -d`; verify both HTTPS sites, owner image flow, R2 countdown/console expiry, graphs, and no unexpected data mutation. Record exact outcomes; do not infer a LAN test from local Docker.
- [x] **Step 3 — final review:** Independent Sol reviews whole extension against spec and tests. Fix findings in their owning tasks, rerun affected checks, then mark T27–T34 COMPLETE and the plan/progress synchronized.

**M12 checkpoint commands (controller only, after full checks/review pass):**

```powershell
git diff --check
git add -- security_lab/analysis.py security_lab/console.py security_lab/storage.py security_lab/templates/storage/detail.html security_lab/templates/console/analysis.html security_lab/static/storage.css security_lab/static/console.css tests/test_analysis.py tests/test_storage_ui.py tests/test_console_ui.py docs/DEMO.md README.md docs/CODE_GUIDE.md docs/superpowers/plans/2026-10-29-image-lockout-graphs-plan.md docs/implementation/PROGRESS.md docs/implementation/DECISIONS.md docs/implementation/reports/T32.md docs/implementation/reports/T33.md docs/implementation/reports/T34.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: graph cryptography measurements and finish demo"
git tag checkpoint/m12-crypto-graphs
```

## Resume and approval gate

The controller must record the user's plan approval in `PROGRESS.md` before dispatching T27. On interruption, preserve the current task phase, assigned files/model, base commit, test output, review status, and next exact action in its report and `PROGRESS.md`; use the bounded WIP procedure in `docs/RESUME.md` if necessary. Never rerun completed tasks solely because a conversation or worker disappeared. Existing account-switch instructions in `docs/RESUME.md` remain authoritative; keep this repository and `.git` together.

The user approved this plan on 29 October 2026 with "okay now implement the plan". T27 began on `feature/image-lockout-graphs` from `d4d2382`.

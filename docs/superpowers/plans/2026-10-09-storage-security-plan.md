# Storage Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user's mandatory model routing, controller-only commands, and durable recovery requirements below override conflicting generic skill defaults. If the plugin is unavailable in a resumed account, this document supplies the executable workflow.

**Goal:** Build an enforced storage website displaying cryptographic evidence and actual generation timings, a separate live admin monitoring website, and a reproducible two-device deployment.

**Architecture:** Two Flask app factories run on separate HTTPS listeners and share SQLite. Application outcomes are signed; a TShark worker captures real traffic and saves PCAPNG. SQL-backed deterministic rules create persistent alerts, and the admin manually blocks storage access by peer IP.

**Tech Stack:** Python>=3.11 (current host 3.13); manifest requirements `Flask>=3.1,<4`, `Werkzeug>=3.1,<4`, `cryptography>=42`, `requests>=2.32,<3`; dev extra `pytest>=8`. SQLite, installed Wireshark/TShark, Docker Compose. These are chosen compatibility floors, not claims about latest versions. The controller checks supported APIs with Context7 and locks actual resolved package versions before implementation consumers run. No frontend build or Streamlit dependency.

**Spec:** `docs/superpowers/specs/2026-10-09-storage-security-design.md`

## Global Constraints

- Independent storage/admin websites, HTTPS ports 8443/8444, separate session secrets and cookie names; no admin routes on storage.
- Bob/Alice storage identities and a console-only admin; encrypted title/text, latest version only, ownership enforced for content and metadata.
- AES-256-GCM, fresh 12-byte nonce, SHA-256 envelope digest, Ed25519 envelope signature; persistent keys outside the database and Git.
- Owner's storage record page shows complete ciphertext, hash, signature, nonce, version, UTC timestamps, verification status, bytes and actual saved encryption/hash/signing durations.
- Timings use `perf_counter_ns`, persist integer nanoseconds, display milliseconds; no benchmark loop, regenerated metrics on refresh, or password hash display.
- Console polls every 2000 ms. Signed audit supplies application outcomes; HTTPS PCAP supplies network metadata. Manual block/unblock only; blocks affect storage admission, not OS firewall.
- R1: 5 distinct TCP destination ports/30 seconds. R2: 5 failed logins/60 seconds per source+username. R3: success within 120 seconds after R2. R4: authenticated foreign existing record denied. R5: R2→R3→R4 in that login session within 300 seconds of success.
- Docker server/client addresses 172.29.0.20/172.29.0.10; configurable two-computer LAN fallback. The host browser's actual address is not relabelled as the container client.
- External attack helpers send ordinary requests and never register a scenario with the framework. No attack/vulnerability controls on either website.
- Persist data, evidence, blocks, task reports and local milestone history. Explicit reset only.
- Build in new_project; the sibling Project directory is a read-only reference and its services/data must not be altered.

## Review Focus

1. Unicode title/body and very short operations: count UTF-8 bytes, escape HTML, and display sub-millisecond durations without fake minimum timings (T04/T09).
2. Restart or interruption between event insert and alert creation: commit both atomically; replay does not duplicate findings (T10/T15).
3. A forged forwarding header or already logged-in blocked client: use the actual peer and deny all subsequent storage requests (T07/T11).
4. Corrupt/missing key files, bad ciphertext or invalid signed events: fail explicitly, expose no plaintext, and do not silently generate replacement keys over existing data (T03/T04/T10).
5. Idle capture versus failed capture, NAT addresses, or absent physical second computer: report observed status/address and actual verification limits (T14/T20).

## Mandatory task delegation and controller protocol

Read repository `AGENTS.md`. It makes this routing durable across account changes.

| Role | Explicit dispatch | Allowed work |
| --- | --- | --- |
| Mechanical worker | `model: gpt-6-luna`, `reasoning_effort: medium`, `fork_turns: none` | Write specified files/tests against frozen interfaces; no independent design |
| Reasoning/complex worker | `model: gpt-6.1-sol`, `reasoning_effort: high`, `fork_turns: none` | Fixed algorithm implementation, security-sensitive integration, diagnosis and concrete resolutions |
| Independent reviewer | `model: gpt-6.1-sol`, `reasoning_effort: high`, `fork_turns: none` | Read supplied files/diffs and acceptance evidence; return findings without edits |
| Controller | Main session | All shell commands, installs, tests, processes, Git, task packets, ledger and decisions |

Each task states its worker and owned files. Dispatch one writer at a time. Workers must not use shell tools, Git, install dependencies, run tests/services, or spawn other agents. The controller supplies the contents of files they need; workers use file-edit tools for owned files. A worker needing a missing design decision returns `NEEDS_SOL_DECISION`, listing the precise gap, instead of inventing behavior.

For each atomic task, the controller performs this sequence:

1. Record the current base commit and task phase in PROGRESS. Supply only the task, applicable contracts, dependencies' interfaces/current files, and its report path.
2. Worker writes the named failing behavioral tests first; controller runs the task's check and records the failure. Check that it fails for the intended missing behavior, rather than merely a broken test setup.
3. Resume the same worker to implement the frozen contract; controller runs that same check and records pass/failure. No command execution is delegated.
4. For unexpected failures, dispatch Sol with the specific files/error evidence to diagnose. Record its resolution in DECISIONS and task report; return predetermined fixes to Luna, or let Sol handle complex code.
5. Complex tasks receive a Sol review before consumers proceed. Mechanical tasks receive controller acceptance checks followed by one Sol review of the milestone batch, conserving repeated context. Review checks both requirements and quality. A task is VERIFIED_PENDING_REVIEW until this gate passes.
6. Record COMPLETE only after required checks/review. Update plan checkboxes, PROGRESS and `docs/implementation/reports/TNN.md`. Preserve all reports.

Task packet template: `Task ID; worker/model/effort; exact owned paths; dependencies; signatures/data shapes; exact assertions; current file contents; forbidden work; report path; next phase`. Report fields: status, changed paths, contracts implemented, controller test evidence, remaining step, concerns. Reviewer packet: task requirements, changed file contents/diff supplied by controller, actual test output, and acceptance checklist. Do not pass the full conversation or whole plan to every worker.

## Durable recovery and command conventions

Recovery starts with `docs/RESUME.md` and `docs/implementation/PROGRESS.md`. Progress files are tracked and survive completion. Never rely on chat history, remembered completion, agent IDs, or account-specific plugin paths. Preserve `.git` when transferring the repo; preserve ignored runtime keys/data separately if retaining existing encrypted records.

All commands below are **controller-only PowerShell**, executed from `new_project`. Define `$labPy` in each resumed shell; it is session state, not a persisted prerequisite.

```powershell
git status --short
git branch --show-current
git log -12 --oneline --decorate
git tag --list 'checkpoint/*'
```

After plan approval, create the feature branch in this already separate directory; if it already exists, use the current recorded branch instead of recreating it. Preserve unrelated changes.

```powershell
git switch -c feature/storage-security
python -m venv .venv
$labPy = Join-Path (Get-Location) '.venv\Scripts\python.exe'
```

T01 creates the dependency manifest. Then the controller installs it and commits its actual resolved lock at M1. On later resumes install the existing lock instead. Commands must finish successfully before advancing.

```powershell
& $labPy -m pip install -e '.[dev]'
& $labPy -m pip freeze --exclude-editable | Set-Content -LiteralPath 'requirements-lock.txt' -Encoding ascii
```

At every milestone: run the listed checks, collect the Sol review, mark those tasks COMPLETE, update milestone state to verified/tag pending, and stage explicit paths. Each command below is a separate command. Abort that checkpoint if checks, review, or commit fail. Tag only a successful milestone commit. Do not overwrite an existing tag; inspect it against the ledger.

If interrupted mid-task, follow the explicit WIP commit procedure in RESUME; do not create a milestone tag or claim the task passed. If interrupted after commit but before tag, identify the actual milestone commit from Git and tag that hash after reconciling evidence. No resets or cleaning are needed for recovery.

## Files and responsibilities

| File | Responsibility |
| --- | --- |
| `pyproject.toml`, `.gitignore`, `requirements-lock.txt` | Dependency declarations/locked installation; runtime exclusions |
| `security_lab/config.py` | Frozen config/env parsing, paths, timestamps and peer normalization |
| `security_lab/schema.sql`, `security_lab/db.py` | SQLite tables and immediate transaction/context helpers |
| `security_lab/identity.py` | Persistent keys and lab TLS certificate management |
| `security_lab/crypto.py` | Canonical encryption envelope, verification, measured operations |
| `security_lab/audit.py` | Signed application event insertion/verification |
| `security_lab/records.py` | Atomic encrypted-record CRUD and denial/integrity auditing |
| `security_lab/auth.py` | Shared login, roles, CSRF, sessions and storage admission guard |
| `security_lab/storage.py` | Storage app factory and normal record routes |
| `security_lab/templates/login.html`, `storage/*.html`, `static/storage.css` | Login and owner record UI with evidence/timings |
| `security_lab/rules.py` | SQL-window deterministic alerts |
| `security_lab/console.py`, `templates/console/*.html`, `static/console.js`, `static/console.css` | Separate admin factory, snapshots, blocks and polling UI |
| `security_lab/packets.py`, `security_lab/capture.py` | Shared packet normalization and supervised live TShark capture |
| `security_lab/pcap.py`, `security_lab/cli.py`, `security_lab/__main__.py` | Offline analysis, init/serve/reset commands and HTTPS launch |
| `Dockerfile`, `Dockerfile.client`, `compose.yaml`, `.dockerignore` | Exactly two devices, persistent server data and real traffic |
| `attacker_tools/client.py`, `attacker_tools/README.md` | Optional ordinary HTTPS/TCP client utilities, independent of framework |
| `tests/*.py`, `tests/conftest.py` | Behavioral contracts, timer/window boundary checks, smoke tests |
| `README.md`, `docs/DEMO.md`, `docs/LAN.md` | Normal usage, evidence interpretation and LAN fallback |
| `docs/implementation/*`, `docs/RESUME.md`, `AGENTS.md` | Durable execution/recovery record |

## Frozen data and interface contracts

These are decisions for workers to implement, not choices they need to make. If a defect is found, Sol resolves it and the controller records the change before consumers run.

### Config and SQLite

`Config` is a frozen dataclass with `data_dir: Path`, `bind_host: str`, `server_ip: str`, `storage_port: int`, `console_port: int`, `capture_interface: str | None`, `tshark_path: str`, `tls_names: tuple[str, ...]`. Defaults: resolved `data/`, `127.0.0.1`, `127.0.0.1`, 8443, 8444, None, detected installed TShark, and localhost/127.0.0.1/server_ip. Environment names are `LAB_DATA_DIR`, `LAB_BIND_HOST`, `LAB_SERVER_IP`, `LAB_STORAGE_PORT`, `LAB_CONSOLE_PORT`, `LAB_CAPTURE_INTERFACE`, `LAB_TSHARK`, `LAB_TLS_NAMES` (comma-separated). If an environ mapping is passed, use only that mapping; otherwise read os.environ. Validate IP literals, distinct ports 1..65535, nonempty names and existing explicitly configured capture executable; explicit bad configuration raises `ValueError` before serving. A missing default TShark is a monitoring-health failure, not a reason to lose storage data.

Functions: `load_config(environ: Mapping[str, str] | None = None) -> Config`, `utc_us() -> int`, `format_utc(value_us: int) -> str`, `normalize_ip(value: str) -> str`. Timestamps use integer epoch microseconds, rendered UTC RFC3339 with microseconds and Z. Normalize IPv4-mapped IPv6 to its IPv4 address for blocking. No client-supplied forwarding headers are trusted.

`connect(config: Config) -> sqlite3.Connection`: file `data_dir/lab.sqlite3`, Row factory, foreign keys enabled, busy timeout 5000 ms, WAL. Decorate `transaction(config: Config) -> Iterator[sqlite3.Connection]` with contextlib.contextmanager: BEGIN IMMEDIATE, commit on success, rollback on exception, always close. `initialize_database(config: Config) -> None` applies the packaged idempotent schema. Connections are not shared across server threads. Store Base64 as standard padded ASCII and hashes as lowercase hex.

Tables (all listed fields are required unless marked nullable; add only the stated indexes/constraints):

- `users(username TEXT PRIMARY KEY, role TEXT CHECK user/admin, password_hash TEXT, created_at_us INTEGER)`.
- `records(id TEXT PRIMARY KEY, owner TEXT REFERENCES users(username), version INTEGER CHECK >=1, nonce_b64 TEXT, ciphertext_b64 TEXT, sha256_hex TEXT, signature_b64 TEXT, created_at_us INTEGER, updated_at_us INTEGER, generated_at_us INTEGER, plaintext_bytes INTEGER, ciphertext_bytes INTEGER, envelope_bytes INTEGER, encryption_ns INTEGER, hashing_ns INTEGER, signing_ns INTEGER)`. Bytes/durations are nonnegative; owner index.
- `events(seq INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, event_id TEXT, time_us INTEGER, kind TEXT, src_ip TEXT, dst_ip TEXT nullable, dst_port INTEGER nullable, username TEXT nullable, session_ref TEXT nullable, record_id TEXT nullable, outcome TEXT, payload_json TEXT, signature_b64 TEXT nullable, capture_id TEXT nullable, frame_number INTEGER nullable, UNIQUE(domain,event_id))`. Domain/kind/source/username/time index and domain/session/time index. Packet signatures are null and explicitly labelled network observations.
- `alerts(id TEXT PRIMARY KEY, domain TEXT, rule TEXT, src_ip TEXT, username TEXT nullable, session_ref TEXT nullable, time_us INTEGER, trigger_event_id TEXT, severity TEXT, summary TEXT, evidence_json TEXT, dedup_key TEXT, UNIQUE(domain,rule,dedup_key))`. Domain/rule/source/username/time index. Evidence JSON is `{event_ids: [str], alert_ids: [str]}`.
- `blocks(ip TEXT PRIMARY KEY, created_at_us INTEGER, created_by TEXT, reason TEXT)`.
- `status(key TEXT PRIMARY KEY, value_json TEXT)`; only live capture status uses key `capture`.

### Keys, envelope and measurement

`KeyRing` holds `aes_key: bytes`, `signing_key: Ed25519PrivateKey`, `storage_session_secret: bytes`, `console_session_secret: bytes`. `load_or_create_keys(config: Config) -> KeyRing` stores raw keys in `data_dir/keys/{aes.key,signing.key,storage-session.key,console-session.key}`. Each is 32 bytes. If existing records/events exist and required key files are missing/corrupt, fail rather than creating replacements. `ensure_certificate(config: Config) -> tuple[Path,Path]` stores `keys/server.crt` and `keys/server.key`, persistent RSA-2048 self-signed certificate (lab-only issuer), DNS/IP SANs from config, validity 365 days; existing mismatching SANs produce a clear error requiring explicit `init --renew-certificate`. Renew certificate only, never encrypted-record/signing keys. Create keys atomically and serialize initialization in the launcher before server threads.

`canonical_bytes(value: dict) -> bytes`: JSON sorted keys, separators `(',', ':')`, ensure_ascii=False, UTF-8. Plaintext is `{title: str, body: str}` without modifying valid content. AAD is `{record_id: str, owner: str, version: int}`. Envelope is `{schema: 1, algorithm: 'AES-256-GCM', record_id, owner, version, nonce_b64, ciphertext_b64, created_at_us, updated_at_us, generated_at_us}`. Hash SHA-256 over envelope bytes; Ed25519 signs those envelope bytes, not the displayed hex digest.

`seal_record(keys: KeyRing, *, record_id: str, owner: str, version: int, title: str, body: str, created_at_us: int, saved_at_us: int, clock: Callable[[],int] = perf_counter_ns) -> dict`: returns all records-table fields with updated/generated timestamp = saved_at_us. Serialize plaintext/AAD, generate nonce and construct AESGCM before timing. Time AES encrypt only, then serialize envelope before timing SHA-256 digest only, then time Ed25519 sign only. Use six clock calls (before/after each operation). Store actual integer deltas and byte counts (encryption input, ciphertext including tag, envelope used by hash/sign). No duration normalization, warm-up loop, or page-load regeneration.

`open_record(keys: KeyRing, row: Mapping[str,Any]) -> dict[str,str]`: reconstruct envelope; validate Base64, compare digest, verify signature, then decrypt/authenticate AESGCM and parse title/body. Raise `IntegrityError` on any verification/format failure; return no partial plaintext. Failures do not expose exception internals to users. Measurement metadata is an observation, not a cryptographic speed guarantee.

### Events, records and auth

Signed application payload contains exactly `domain='live'`, `event_id` (UUID hex), `time_us`, `kind`, `src_ip`, nullable `dst_ip/dst_port/username/session_ref/record_id`, `outcome`. No form bodies, passwords, keys or cookie values. Kinds: `login_failure`, `login_success`, `admin_login_failure`, `admin_login_success`, `record_created`, `record_updated`, `record_read`, `foreign_record_denied`, `integrity_failure`, `blocked_request`, `logout`, `admin_block`, `admin_unblock`.

`append_app_event(conn: Connection, keys: KeyRing, payload: dict) -> str` signs canonical payload, inserts normalized columns+payload/signature idempotently and returns event_id. `verify_app_event(keys: KeyRing, row: Mapping[str,Any]) -> bool` checks signature and agreement of indexed fields with signed payload. T10 adds evaluation immediately after a newly inserted application event, in the caller's transaction. Invalid signed outcomes are not used by rules. Snapshot inspection reports invalid evidence rather than silently trusting it.

`save_record(config: Config, keys: KeyRing, *, owner: str, record_id: str | None, title: str, body: str, src_ip: str, session_ref: str) -> dict`: create UUID hex when new; validate title 1..120 characters/body 1..10000 characters and non-whitespace, preserve valid original text; check owner, verify existing record before edit, increment version under BEGIN IMMEDIATE, seal/store latest and append signed save event atomically. `list_records(config: Config, keys: KeyRing, *, owner: str, src_ip: str, session_ref: str) -> list[dict]` returns only owned, verified `id,title,version,created_at_us,updated_at_us` for listing; a corrupt owned record logs integrity_failure before raising the generic error. `read_record(config: Config, keys: KeyRing, *, owner: str, record_id: str, src_ip: str, session_ref: str) -> tuple[dict,dict]` returns stored row + plaintext after owner and integrity checks. Raise `RecordMissing`/`RecordDenied`/`IntegrityError` with 404/403/409 mapping; invalid form data raises ValueError and maps to400 with the submitted escaped form retained. Signed denied/integrity events must commit before the exception reaches a route; do not roll them back by raising inside their transaction. A missing ID produces 404, not R4. Creation/edit failures leave no half-saved version.

`configure_auth(app: Flask, config: Config, keys: KeyRing, *, required_role: str) -> None` installs shared `/login` GET/POST and `/logout` POST. Names: user app cookie `storage_session`, admin app `console_session`; HttpOnly/Secure/SameSite=Lax, distinct secrets, MAX_CONTENT_LENGTH=65536. Session keys are username, role, session_ref, csrf. Username lookup lowercases/strips username; password is unchanged. Use explicit Werkzeug scrypt password hashing. Fresh random opaque session_ref at successful login; no cookie-derived identifier. Missing/incorrect CSRF gives 400 and is not counted as a wrong password. Invalid credentials or wrong role gives 401 with no authenticated identity; successful login clears old session and redirects 303 to `/`. `require_login(role: str)` guards protected views. `csrf_token() -> str` and `check_csrf() -> None` handle forms using field name `csrf_token` and compare_digest against session['csrf']; all mutating routes enforce CSRF. Storage auth outcomes feed R2/R3; console auth also has signed logs but is excluded from those storage rules (use outcome `console_login_denied`/`console_login_ok` and kinds `admin_login_failure`/`admin_login_success`).

Storage-only admission checks blocks before every request, using `request.remote_addr` normalized, never X-Forwarded-For. A block returns 403 even for an existing authenticated session and records `blocked_request`. Admission never applies to the admin app. Unknown/invalid peer addresses are recorded as `unknown` and excluded from source-IP rules, never replaced with a header.

### Rules and packets

`evaluate_event(conn: Connection, keys: KeyRing, domain: str, event_id: str) -> list[str]` operates within the insertion transaction. Query only the event's domain and windows inclusive `[t-window,t]`, with ingestion sequence <= current sequence, deterministic ordering `(time_us,seq)`. Live producers use server time for app events; captures preserve packet timestamps. On timestamp regression show a monitoring warning; do not invent packet ordering or silently rewrite original timestamps. Offline inputs are sorted by `(time_us,frame_number)` before insert. No in-memory state is required; restart queries stored windows.

R1 uses incoming TCP SYN without ACK, addressed to configured server; compare distinct port count before and after current event inside the same 30-second window. Emit only when before<5 and after>=5. Evidence is the newest representative event of each distinct port in the crossing window, sorted deterministically. R2 similarly compares verified failure count before/after current event over 60 seconds for source+canonical username; evidence is the latest five failures. Counts of other usernames/sources, malformed forms, blocks, and invalid signed audit entries do not qualify. No fixed cooldown.

R3 looks up latest matching R2 where `0 <= login_time-R2_time <=120s`; dedup key login event_id. R4 dedup key denied event_id. R5 finds R3 for the same live source/username/session_ref and `0 <= denied_time-login_time <=300s`; dedup key session_ref, one linked alert per login session. R5 evidence includes R2/R3/R4 alert IDs and their application event IDs. R1/R2 dedup key is crossing event_id. Alert IDs are SHA-256 of canonical `{domain,rule,dedup_key}`; insert-or-ignore prevents duplicates. Severity labels R1 info, R2 warning, R3 review, R4 blocked, R5 incident. A blocked access attempt is not a disclosure.

TShark field order: `frame.number`, `frame.time_epoch`, `ip.src`, `ipv6.src`, `ip.dst`, `ipv6.dst`, `tcp.srcport`, `tcp.dstport`, `tcp.flags.syn`, `tcp.flags.ack`, `tcp.seq_raw`, `tcp.analysis.retransmission`. Parse decimal epoch with Decimal to integer microseconds. IPv4/IPv6 fields pick the nonempty address. Ignore rows without valid source/destination/port or non-incoming SYN-without-ACK; deduplicate retransmissions using src/dst/srcport/dstport/seq within that capture. The console's traffic list is explicitly connection attempts, not every network packet.

`parse_packet_fields(line: str, *, capture_id: str, domain: str, server_ip: str) -> dict | None`; packet event_id=`capture_id:frame_number`, kind=`connection_attempt`, outcome=`observed`, signature null, capture/frame references retained. Packet payload additionally retains `src_port`, `tcp_seq_raw` and `retransmission` for deduplication. `insert_packet(config: Config, keys: KeyRing, event: dict) -> bool` inserts/evaluates in one immediate transaction. Valid but irrelevant rows return None; malformed column counts/numbers raise PacketParseError and are reported by the supervisor without killing capture.

`CaptureWorker(config, keys)` has `start()`, `stop()`, `health() -> dict`. Spawn TShark without shell, `-n -l -i <interface> -w <file> -P -T fields` plus exact `-e` fields, store a UUID capture_id/PCAPNG path. Read metadata stdout and drain stderr concurrently. No restrictive single-web-port capture filter: scans to closed ports must be recorded. Scope ingestion to configured server. Store status state starting/running/degraded/stopped, started_at_us, last_packet_at_us, capture_path, error. Process exit is degraded; silence on an idle network is not an error. On stop, terminate/wait for the owned process and preserve readable capture. Verify exact supported command on the target TShark version; if simultaneous capture+fields is incompatible, Sol supplies a fixed dumpcap/TShark pipe solution before implementation changes.

`analyze_pcap(config: Config, keys: KeyRing, path: Path) -> dict`: SHA-256 file bytes defines `domain='offline:'+digest` and capture_id=digest, parse with TShark `-r` and the same fields. Offline replay generates R1 from packet observations only, not invented login/access outcomes. Duplicate import is idempotent; offline data must not affect live alerts/blocks/health. Console has a domain selector; default live, offline domain identified by capture hash.

## Milestone M1 — Foundation

### Task T01: Config, dependency manifest and schema definition

**Worker:** gpt-6-luna. **Depends:** approved plan and controller branch setup.
**Owned:** `pyproject.toml`, `.gitignore`, `security_lab/__init__.py`, `security_lab/config.py`, `security_lab/schema.sql`, `tests/test_config.py`.
**Interfaces:** Config/env/time/IP contracts and the exact tables above. pyproject uses setuptools.build_meta (setuptools>=68 and wheel); package discovery includes security_lab only, with schema.sql, templates/**/*.html, static/*.css and static/*.js as package data. Set pytest testpaths=['tests']; dev extra pytest; require Python>=3.11. Exact ignore entries: `.venv/`, `data/`, `__pycache__/`, `.pytest_cache/`, `*.py[cod]`, `.env`, `.superpowers/`; retain all `docs/implementation/` files.

- [ ] Write `test_defaults`, `test_distinct_ports`, `test_utc_and_mapped_ip`; assertions include `cfg.storage_port == 8443`, `cfg.console_port == 8444`, invalid equal ports raise ValueError, `format_utc(0) == '1970-01-01T00:00:00.000000Z'`, mapped `::ffff:192.168.1.2` becomes `192.168.1.2`.
- [ ] Controller installs manifest, runs `& $labPy -m pytest tests/test_config.py -q`, and records intended red.
- [ ] Implement exact config/contracts and literal SQL schema. Do not choose dependencies beyond the frozen stack or change table names.
- [ ] Controller reruns the same check; expected PASS. Capture resolved versions in requirements-lock.txt.

### Task T02: Transaction helpers and shared test fixtures

**Worker:** gpt-6-luna. **Depends:** T01.
**Owned:** `security_lab/db.py`, `tests/conftest.py`, `tests/test_db.py`.
**Interfaces:** connect, transaction, initialize_database above. Fixture `config` uses tmp_path data dir; no real project data touched. Later task fixtures append only their own dependencies.

- [ ] Write `test_schema_idempotent`, `test_transaction_rolls_back`, `test_distinct_connections`. Assert two initializations preserve a inserted user; failed transaction leaves zero inserted rows; separate connections see committed rows and have foreign_keys=1.
- [ ] Controller runs `& $labPy -m pytest tests/test_db.py -q` for red.
- [ ] Implement specified helpers and temporary config fixture; use parameterized SQL and package-relative schema reading.
- [ ] Controller reruns test_db; expected PASS.

**M1 review/checkpoint — controller:** Sol reviews T01-T02. Run config+db checks and `git diff --check`; update reports/ledger/checklists, then:

```powershell
git add -- pyproject.toml .gitignore requirements-lock.txt security_lab/__init__.py security_lab/config.py security_lab/schema.sql security_lab/db.py tests/conftest.py tests/test_config.py tests/test_db.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M1): add configuration and SQLite foundation'
git tag -a checkpoint/m1-foundation -m 'M1 verified: configuration and database'
git status --short
```

## Milestone M2 — Persistent cryptography and signed audit

### Task T03: Persistent identities and HTTPS certificate

**Worker:** gpt-6.1-sol (key lifecycle/certificate work). **Depends:** T02.
**Owned:** `security_lab/identity.py`, `tests/test_identity.py`; append `keys` fixture in `tests/conftest.py`.
**Interfaces:** KeyRing, load_or_create_keys, ensure_certificate above. Use cryptography certificate APIs checked with Context7; no CLI OpenSSL dependency.

- [ ] Write persistence tests: loading twice yields equal AES/session keys and signing public bytes; AES length==32; app secrets differ; all generated secret files live below configured data_dir/keys. Missing aes.key with an existing database record raises an explicit error. Certificate SAN includes localhost, 127.0.0.1 and configured server IP; normal startup preserves its fingerprint. The controller separately inspects staged paths before committing.
- [ ] Controller runs `& $labPy -m pytest tests/test_identity.py -q` for red.
- [ ] Implement key/certificate contracts; reject malformed lengths/SAN mismatch. Explicit renewal returns a new cert while AES/signing key fingerprints remain identical.
- [ ] Controller reruns; expected PASS; fresh Sol reviewer approves lifecycle before T04.

### Task T04: Measured encryption, envelope hash and signature

**Worker:** gpt-6.1-sol (cryptographic implementation). **Depends:** T03.
**Owned:** `security_lab/crypto.py`, `tests/test_crypto.py`.
**Interfaces:** canonical_bytes, seal_record, open_record, IntegrityError and exact envelope above.

- [ ] Write `test_round_trip_unicode`, `test_tamper_rejected`, `test_fresh_nonce`, `test_exact_timer_scopes`. Assert unicode title/body round-trip; ciphertext bytes do not contain submitted plaintext; changed owner/ciphertext/nonce/signature/timestamp each raises IntegrityError; identical input sealed twice has different nonce.
- [ ] Timer assertion: injected clock `iter([100,160,200,220,300,350]).__next__` produces encryption_ns==60, hashing_ns==20, signing_ns==50. `plaintext_bytes` equals canonical UTF-8 length; `ciphertext_bytes == plaintext_bytes+16`; `envelope_bytes` matches canonical envelope length. Six calls only, no read-time regeneration.
- [ ] Controller runs `& $labPy -m pytest tests/test_crypto.py -q` for red.
- [ ] Implement exact operation scopes, encoding and verification ordering using the fetched official APIs. Do not generate artificial benchmark samples.
- [ ] Controller reruns; expected PASS; fresh Sol reviewer approves before record consumers.

### Task T05: Signed, indexed audit event persistence

**Worker:** gpt-6.1-sol (evidence integrity). **Depends:** T04.
**Owned:** `security_lab/audit.py`, `tests/test_audit.py`.
**Interfaces:** append_app_event and verify_app_event; T10 later adds rule evaluation hook. Caller owns transaction; duplicate event insertion is a no-op.

- [ ] Write signed event tests: valid event verifies; changed indexed username or payload/signature fails; identical event_id inserts one row; event payload excludes passwords/title/body/cookies/private keys.
- [ ] Controller runs `& $labPy -m pytest tests/test_audit.py -q` for red.
- [ ] Implement canonical signed payload and column agreement checks. No HMAC substitution, audit outbox, separate ingestion process or signing-on-page-load.
- [ ] Controller reruns; expected PASS.

**M2 review/checkpoint — controller:** Sol reviews audit plus unresolved concerns from T03/T04, without redoing already resolved reviews. Run identity/crypto/audit tests, diff check, update records, then:

```powershell
git add -- security_lab/identity.py security_lab/crypto.py security_lab/audit.py tests/conftest.py tests/test_identity.py tests/test_crypto.py tests/test_audit.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M2): add measured record cryptography and signed audit'
git tag -a checkpoint/m2-crypto -m 'M2 verified: keys encryption hashes signatures timings'
git status --short
```

## Milestone M3 — Storage website and owner evidence

### Task T06: Atomic record service

**Worker:** gpt-6.1-sol (transactions, authorization, error auditing). **Depends:** T05.
**Owned:** `security_lab/records.py`, `tests/test_records.py`.
**Interfaces:** save_record/list_records/read_record and errors above; read services require source/session context. Seed users in tests using explicit scrypt hashes, not launcher dependency.

- [ ] Write tests asserting create version1, edit version2 with preserved creation timestamp/new updated timestamp and nonce; inject wall-clock values1000000/2000000us rather than sleeping. Only latest row exists; Bob listing excludes Alice; foreign existing access raises RecordDenied and persists exactly one signed foreign_record_denied event; missing ID is RecordMissing, not foreign denial.
- [ ] Assert integrity failure returns no plaintext, persists integrity_failure, and does not overwrite bad record. Concurrent updates serialize and obtain distinct increasing versions. Failed save leaves neither partial ciphertext nor a success event.
- [ ] Controller runs `& $labPy -m pytest tests/test_records.py -q` for red, then after implementation for PASS.
- [ ] Sol reviewer checks transaction/error commit ordering before routes consume it.

### Task T07: Shared login, CSRF and storage admission

**Worker:** gpt-6-luna; fixed security decisions above, escalate any gaps to Sol. **Depends:** T06.
**Owned:** `security_lab/auth.py`, `security_lab/templates/login.html`, `tests/test_auth.py`.
**Interfaces:** configure_auth/require_login/csrf helpers above. Tests construct tiny Flask apps with this module and a protected test route, avoiding dependency on T08/T11.

- [ ] Write tests: correct Bob credentials authenticate user app; admin cannot authenticate user app; Bob cannot authenticate admin app; invalid/missing CSRF gives400, valid wrong password gives401 and login_failure, correct gives303/login_success with new session_ref. Failure clears any old authenticated identity.
- [ ] Assert separate cookie names/secrets reject cross-app sessions; storage blocked peer gives403 even after prior login; forged X-Forwarded-For cannot bypass block; admin site unaffected. Use test_client base_url=https://localhost and actual REMOTE_ADDR overrides.
- [ ] Controller runs `& $labPy -m pytest tests/test_auth.py -q` for red.
- [ ] Implement exact role/session/CSRF/admission behavior and minimal standalone escaped login template.
- [ ] Controller reruns; expected PASS.

### Task T08: Storage app factory and regular routes

**Worker:** gpt-6-luna. **Depends:** T07.
**Owned:** `security_lab/storage.py`, `tests/test_storage.py`, `tests/conftest.py` (append `storage_app`/`storage_client` fixtures using temporary config/keys and seeded test users).
**Interfaces:** `create_storage_app(config: Config, keys: KeyRing) -> Flask`. Routes `/` GET list, `/records/new` GET/POST create, `/records/<id>` GET detail, `/records/<id>/edit` GET/POST edit; configure_auth required_role='user'. Successful save redirects303 to detail. Render `storage/list.html` with `records`; `storage/form.html` with `form={title,body}`, `record_id` (None when new) and optional `error`; `storage/detail.html` with `record` (stored row), `plaintext={title,body}`, `verified=True`; errors with `message`. Always pass `csrf_token` string and `username` to templates. POST names are title/body/csrf_token. Integrity error409, foreign403, missing404, invalid form400. No console/scenario/attack endpoints.

- [ ] Write route tests: unauthenticated redirects login, create/edit with valid CSRF yields303, GET evidence uses read_record, forged foreign URLs return403 for view and edit, missing ID404, absent CSRF400, oversized payload413.
- [ ] Controller runs `& $labPy -m pytest tests/test_storage.py -q` for red.
- [ ] Implement routes against frozen services; no duplicated crypto or custom detector calls. Minimal templates needed for first green are owned by T09, so supply template stubs through tests using DictLoader until T09 completes.
- [ ] Controller reruns; expected PASS.

### Task T09: Owner record UI and measured performance view

**Worker:** gpt-6-luna. **Depends:** T08.
**Owned:** `security_lab/templates/storage/base.html`, `list.html`, `form.html`, `detail.html`, `error.html`, `security_lab/static/storage.css`, `tests/test_storage_ui.py` (template filenames all under storage/).
**Interfaces:** T08 passes record row, decrypted title/body, CSRF, and verified status. Server-render full Base64 ciphertext/nonce/signature and hexadecimal hash in selectable wrapping text; long values never truncated. Show version/created/updated/generated UTC times and labels SHA-256 hash / Ed25519 signature. Show bytes for plaintext/ciphertext/envelope and durations `ns/1_000_000`, formatted to six decimals ms.

- [ ] Write HTML tests: owner sees exact stored ciphertext/hash/signature; title `<script>` renders escaped; foreign evidence stays inaccessible. Inject metrics60/20/50ns and assert visible `0.000060`, `0.000020`, `0.000050` ms. Refresh twice leaves nonce/signature/metrics unchanged; GET never calls seal_record.
- [ ] Controller runs `& $labPy -m pytest tests/test_storage_ui.py -q` for red.
- [ ] Implement straightforward login/list/create/edit/navigation and a detail evidence section. Performance view is a numeric three-row table plus three CSS bars scaled to the largest duration (zero denominator guarded). Label input sizes and “Measured operation durations for this saved version”; no fabricated speed superiority or experiment runner.
- [ ] Controller reruns; expected PASS; browser inspection occurs at T20 rather than a redundant layout test suite.

**M3 review/checkpoint — controller:** Sol reviews auth/routes/UI and their interaction with T06, focusing on owner-only evidence, independent cookies and real timings. Run records/auth/storage/storage_ui tests and diff check, update records, then:

```powershell
git add -- security_lab/records.py security_lab/auth.py security_lab/storage.py security_lab/templates/login.html security_lab/templates/storage security_lab/static/storage.css tests/conftest.py tests/test_records.py tests/test_auth.py tests/test_storage.py tests/test_storage_ui.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M3): add protected storage website and crypto evidence UI'
git tag -a checkpoint/m3-storage -m 'M3 verified: login records owner evidence and timings'
git status --short
```

## Milestone M4 — Deterministic rules and separate admin website

### Task T10: Atomic SQL-window rule evaluation

**Worker:** gpt-6.1-sol (algorithm and evidence linking). **Depends:** T09.
**Owned:** `security_lab/rules.py`, evaluation hook in `security_lab/audit.py`, `tests/test_rules.py`.
**Interfaces:** evaluate_event and rule/dedup contracts above. append_app_event calls it only on new insertion; SQL queries and event+alert commit use the same connection. Packet ingestion T13 uses the same evaluator.

- [ ] Write fixed-time fixtures (no sleeps): four distinct ports emit noR1, fifth at30s inclusive emitsR1, repeated port adds no distinct count; source/destination/domain separation holds. Four valid failures emit noR2; fifth at60s inclusive emitsR2; unknown usernames count, different username/IP and invalid signatures do not.
- [ ] Assert R3 at exactly120s qualifies and120s+1us does not; R4 only foreign existing authenticated denial; R5 at exactly300s qualifies and300s+1us/different session/source does not. R1/R2 crossing emits once while above threshold and rearms after membership falls below; re-evaluation/restart adds no duplicates. Forced evaluation failure rolls back the inserted event and all findings.
- [ ] Controller runs `& $labPy -m pytest tests/test_rules.py -q` for red.
- [ ] Implement the frozen SQL algorithm. Validate indexed fields against signed payload before application events count. Hash-based alert IDs and unique dedup are mandatory; no fixed cooldown, probability score, memory cache or arbitrary scenario label.
- [ ] Controller reruns; expected PASS; fresh Sol reviewer checks boundaries and restart behavior before console consumption.

### Task T11: Separate admin app, snapshots and manual block actions

**Worker:** gpt-6-luna. **Depends:** T10.
**Owned:** `security_lab/console.py`, `tests/test_console.py`.
**Interfaces:** `create_console_app(config: Config, keys: KeyRing) -> Flask`, `snapshot(config: Config, keys: KeyRing, domain: str='live') -> dict`. Routes `/` GET, `/api/snapshot?domain=live` GET, `/blocks` POST(ip/reason/csrf_token), `/blocks/<ip>/remove` POST(csrf_token); admin auth+CSRF. Snapshot keys `domain, domains, capture, events, alerts, blocks`; domains is sorted list of available domain strings. Events expose normalized public event columns plus `time_utc` and `signature_valid` (bool for audit, None for packet); alerts expose public alert columns plus parsed `evidence` and time_utc; omit payload_json/signature raw/private fields. Newest100 events/alerts by time_us/seq or id; blocks expose ip/created_by/reason/created_at_us. Invalid signatures remain visibly marked, never labelled verified. Dashboard receives initial `snapshot` and `csrf_token`. No record plaintext/private key/password hashes in snapshot.

- [ ] Write tests: ordinary user cannot authenticate/view snapshot; user session cookie cannot authorize console; admin succeeds; POST block with valid CSRF normalizes actual IP, persists and audits; absent CSRF gives400; unblock removes and audits. For block/unblock events, src_ip is the admin peer and dst_ip is the target IP, preserving which address was acted upon. Existing Bob client becomes403 on storage after admin block; XFF cannot bypass; unblocking restores normal access. Default snapshot excludes offline data.
- [ ] Controller runs `& $labPy -m pytest tests/test_console.py -q` for red.
- [ ] Implement queries and actions using existing contracts; validate IP and reason length<=200, reject empty/invalid addresses with400, redirect303 to dashboard after successful action. Block/unblock audit payload uses dst_ip for the target and src_ip for the actual admin peer. Add no firewall or automatic ban logic.
- [ ] Controller reruns; expected PASS.

### Task T12: Live console page

**Worker:** gpt-6-luna. **Depends:** T11.
**Owned:** `security_lab/templates/console/dashboard.html`, `security_lab/static/console.js`, `security_lab/static/console.css`, `tests/test_console_ui.py`.
**Interfaces:** Snapshot shape and routes T11. Page shows capture status/error, incoming connection attempts, signed application events, R1-R5 alert reasons/evidence, flagged sources and associated usernames, blocks with actions, and live/offline domain selector. “Flagged username” is labelled attempted/authenticated context, not proven attacker identity.

- [ ] Write HTML tests proving admin-only dashboard and visible forms/CSRF, source/account distinction, encrypted-network metadata label, empty state and capture-degraded message. Test snapshot escaping contract using a malicious-looking username; dynamic text must use textContent, not innerHTML interpolation.
- [ ] Controller runs `& $labPy -m pytest tests/test_console_ui.py -q` for red.
- [ ] Implement fetch polling every2000ms, retain current content on failed fetch and display connection warning, prevent overlapping in-flight polls. Render with DOM textContent; keep block/unblock ordinary POST forms. No attack launch controls or full-page reload.
- [ ] Controller reruns; expected PASS. T20 verifies actual updates in a browser.

**M4 review/checkpoint — controller:** Sol reviews separate app identity, manual controls and polling; T10 review remains part of evidence. Run rules/console/console_ui and relevant auth tests, then:

```powershell
git add -- security_lab/rules.py security_lab/audit.py security_lab/console.py security_lab/templates/console security_lab/static/console.js security_lab/static/console.css tests/test_rules.py tests/test_console.py tests/test_console_ui.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M4): add deterministic detection and separate admin console'
git tag -a checkpoint/m4-console -m 'M4 verified: live alerts and manual IP blocks'
git status --short
```

## Milestone M5 — Actual traffic and saved-PCAP analysis

### Task T13: Packet field normalization and atomic insertion

**Worker:** gpt-6-luna. **Depends:** T10.
**Owned:** `security_lab/packets.py`, `tests/test_packets.py`.
**Interfaces:** parse_packet_fields/insert_packet and exact field order above. Use tab separation, Decimal timestamps and capture/frame IDs. Parser itself is stateless; dedup via DB checks for the same capture/src/dst/ports/seq metadata persisted in packet payload.

- [ ] Write fixtures: IPv4 and IPv6 incoming SYN accepted; ACK-only/outgoing/nonconfigured server ignored; Decimal `1700000000.123456` maps to1700000000123456; duplicate frame and SYN retransmission create one observation; five distinct server ports trigger actualR1 through insert_packet.
- [ ] Controller runs `& $labPy -m pytest tests/test_packets.py -q` for red.
- [ ] Implement exact parser/insertion with no packet decoding of encrypted login/content. Reject malformed fields and preserve capture references.
- [ ] Controller reruns; expected PASS.

### Task T14: Supervised live TShark capture

**Worker:** gpt-6.1-sol (process lifecycle/capture integration). **Depends:** T13.
**Owned:** `security_lab/capture.py`, `tests/test_capture.py`.
**Interfaces:** CaptureWorker and status above; feed accepted lines to insert_packet. Dependencies injected for process simulation in unit tests. Subagent writes lifecycle code; actual commands/process verification remain controller-only.

- [ ] Write fake-process tests: stdout produces a persisted packet+alert; stderr/process failure recordsdegraded; idle running process staysrunning; stop waits/cleans only owned process and retains capturepath; configured interface and all fields appear in argv without shell=True.
- [ ] Controller runs `& $labPy -m pytest tests/test_capture.py -q` for red.
- [ ] Implement bounded stdout/stderr supervision, explicit startup failure and shutdown, PCAP naming per UUID. Do not assume Windows can observe Docker bridge traffic from the host.
- [ ] Controller reruns; expected PASS; Sol reviewer approves lifecycle before launcher.

### Task T15: Idempotent offline PCAP import

**Worker:** gpt-6.1-sol (time order/domain integration). **Depends:** T14.
**Owned:** `security_lab/pcap.py`, `tests/test_pcap.py`.
**Interfaces:** analyze_pcap; return `{domain: str, inserted_events: int, alert_count: int}`. File hash domain/capture identity, shared TShark fields and sorted normalization.

- [ ] Write import tests using injected decoded fields and a fixture capture: five distinctports produces offlineR1, second import inserts0/adds0alerts, live snapshot unchanged, no R2-R5 without app events, file path/spaces do not invoke a shell, malformed file reports an explicit error.
- [ ] Controller runs `& $labPy -m pytest tests/test_pcap.py -q` for red.
- [ ] Implement stream/hash/import contract. Do not invent application evidence or duplicate live observations under live scope during offline replay.
- [ ] Controller reruns; expected PASS. Real PCAP readability is verified in Docker at T20.

**M5 review/checkpoint — controller:** Sol reviews packet normalization/domain isolation plus unresolved capture concerns. Run packets/capture/pcap and rule tests, then:

```powershell
git add -- security_lab/packets.py security_lab/capture.py security_lab/pcap.py tests/test_packets.py tests/test_capture.py tests/test_pcap.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M5): add live packet capture and idempotent PCAP analysis'
git tag -a checkpoint/m5-capture -m 'M5 verified: actual network evidence and replay'
git status --short
```

## Milestone M6 — HTTPS launcher and two devices

### Task T16: CLI, seeding, listener lifecycle and explicit reset

**Worker:** gpt-6.1-sol (cross-module integration). **Depends:** T12/T15.
**Owned:** `security_lab/cli.py`, `security_lab/__main__.py`, `tests/test_cli.py`.
**Interfaces:** `main(argv: list[str] | None=None) -> int`; commands `init [--renew-certificate]`, `serve`, `analyze-pcap <path>`, `reset --confirm RESET`. Config uses environment above. Init creates dirs/schema/keys/cert and missing seeds only; ordinary init/serve never resets existing records.

- [ ] Seed bob/BobDemo!2026, alice/AliceDemo!2026, admin/AdminDemo!2026 as explicitly documented lab accounts with scrypt hashes. Initial records use IDs `00000000000000000000000000000001` (Bob), `00000000000000000000000000000002` (Alice), titles “Bob's record”/“Alice's record” and short ordinary text. No hardcoded session/encryption keys. Credentials are lab defaults, not user secrets.
- [ ] Write tests asserting init twice preserves edited data, roles/seeds valid, two app factory ports/secrets differ, analyze delegates offline, normal shutdown closes only owned listeners/capture. Reset without exactconfirmation does nothing; explicit reset clears DB/captures/blocks and seeds clean state while preserving existing key files. Resolve all deletion targets inside configured data_dir before removal; refuse unsafe root/repo target.
- [ ] Controller runs `& $labPy -m pytest tests/test_cli.py -q` for red.
- [ ] Implement two threaded Werkzeug make_server HTTPS listeners for this local lab, same configured certificate, no debugger/reloader; initialize once before threads. Launch CaptureWorker only with configured interface; missing capture is reported on console. Stop listeners/capture on interruption. Create `data_dir/server.pid` atomically with JSON pid/started_at_us on serve; remove the owned marker on normal stop. Serve/reset refuse an existing marker and explain how to inspect the recorded process before removing only a stale marker. Preserve data during recovery.
- [ ] Controller reruns; expected PASS; Sol reviewer approves startup/reset/certificate integration.

### Task T17: Docker server and independent client device

**Worker:** gpt-6-luna. **Depends:** T16.
**Owned:** `Dockerfile`, `Dockerfile.client`, `compose.yaml`, `.dockerignore`.
**Interfaces:** Two services `server` and `client` on internal subnet172.29.0.0/24, server.20/client.10. Server Python3.13 slim installs tshark noninteractively plus locked deps/project; command `python -m security_lab serve`. Server env LAB_BIND_HOST=0.0.0.0, LAB_SERVER_IP=172.29.0.20, LAB_CAPTURE_INTERFACE=eth0, LAB_TLS_NAMES=localhost,127.0.0.1,172.29.0.20,server; add NET_RAW/NET_ADMIN for capture; persist `./data:/app/data`; localhost8443/8444 published. Client Python3.13 slim installs requests, mounts `./attacker_tools:/tools:ro`, `./tests:/tests:ro` (smoke checks only) and `./data/keys/server.crt:/certs/server.crt:ro`; sleeps to remain available, no detector/controlserver. Cert must exist via controller init before client mount/start. Manifest/SQL/templates/static are copied into server image; source packaging includes them.

- [ ] Implement the exact two-service configuration, healthcheck using HTTPS with server cert against `/login` and no credential leak. No old-project subnet/container names, Docker socket mount or shared privileged host networking. Exclude .git/.venv/data/docs reports from build context where unnecessary.
- [ ] Controller runs `docker compose config --quiet`, expected exit0; checks subnet and exactlytwo services with `docker compose config --services`.
- [ ] No automated tests that simply duplicate YAML values; actual build/traffic check is T20.

**M6 review/checkpoint — controller:** Sol reviews launch/config integration and two-device capture assumptions. Run cli plus current unit suite; validate compose; then:

```powershell
git add -- security_lab/cli.py security_lab/__main__.py Dockerfile Dockerfile.client compose.yaml .dockerignore tests/test_cli.py docs/implementation docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'feat(M6): add HTTPS launch and two-device Docker deployment'
git tag -a checkpoint/m6-deployment -m 'M6 verified: persistent launch and deployment configuration'
git status --short
```

## Milestone M7 — External clients, walkthrough and verified delivery

### Task T18: External attacker convenience client

**Worker:** gpt-6-luna. **Depends:** T17.
**Owned:** `attacker_tools/client.py`, `attacker_tools/README.md`, `tests/test_attacker_client.py`.
**Interfaces:** Standalone `main(argv: list[str] | None=None) -> int` with argparse subcommands `login-attempts --url --username --password-file --limit [--delay] --ca`, `request-record --url --username --password --record-id --ca`, `probe --host --ports [--timeout]`. Bound limit1..1000, default5; delay>=0, timeout default1 second. Function `extract_csrf(html: str) -> str` uses stdlib HTMLParser for input name csrf_token. Use requests Session and real HTTPS forms, never framework internals. Password file is external untracked input; do not include it in Git. No client-written framework events.

- [ ] Write tests with fake requests/socket: each password attempt first GETs /login for the current CSRF, POSTs username/password/csrf_token without following redirects, continues on401, stops on first303 success or403 blocked, and reports other errors as nonzero. Passwords stay in input order up to limit and are not echoed. Record request performs ordinary successful login then GETs the supplied record URL; probe uses only explicit host/ports; TLS verifies with provided CA and is never silently disabled.
- [ ] Controller runs `& $labPy -m pytest tests/test_attacker_client.py -q` for red.
- [ ] Implement the bounded fixed behavior; print attempt index/status/response outcome without passwords, cookies or keys. Do not integrate client into framework services, console buttons or a fixed attack progression. These are optional presenter tools, not the project's detector.
- [ ] Controller reruns; expected PASS.

### Task T19: Short README, presentation and physical LAN fallback

**Worker:** gpt-6-luna. **Depends:** T18.
**Owned:** `README.md`, `docs/DEMO.md`, `docs/LAN.md`.
**Interfaces:** Exact commands/routes/config from previous tasks; do not invent unimplemented flags. No documentation-mirroring tests.

- [ ] Write quickstart: controller venv/install/init, Docker build/up, https://localhost:8443 storage and8444admin, documented certificate trust, seededcredentials, normal create/edit and owner crypto/timing evidence, livecapture preflight, independently chosen externalclient examples, adminBlock/Unblock, PCAPimport, restart/reset.
- [ ] LAN guide: A's LAB_BIND_HOST=0.0.0.0/LAB_SERVER_IP actualIP/LAB_TLS_NAMES actualnames/LAB_CAPTURE_INTERFACE selectedTShark interface; `tshark -D` inventory; init certificate SANs before serve; B uses A's HTTPSIP and copied publicservercert for verification. Document required inbound ports, adminlogin, observed NAT/source limits and capturepermissions. Certificate/private/encryption keys are never copied to attackerB except the publiccertificate.
- [ ] Include four security-goal evidence mappings; explain SHA-256 hash versus Ed25519 signature, generation timings/input sizes and HTTPS metadata versus signed outcomes. Explain local history/resume files and manual reset. Keep walkthrough executable without a mandatory five-attack scenario.
- [ ] Controller checks every listed command against CLI help/compose config and notes physical verification limit.

### Task T20: End-to-end smoke contracts and final reasoning review

**Worker:** gpt-6.1-sol for smoke test design/code and final review; controller runs commands/browser. **Depends:** T19.
**Owned:** `tests/test_smoke.py`, `tests/docker_smoke.py`; update docs only for verified mismatches through designated worker fixes.
**Interfaces:** Use real routes/CSRF/TLS, not attack-only endpoints. Unit/in-process smoke covers recordcreation/evidence/denial/block/unblock/restart usingtemporary data; Docker smoke runs independently from the clientdevice via requests and sockets and produces no predeclared detector alerts. Fixtures may be security tests; they are not a product scenario mode.

- [ ] Write smoke tests proving normal Bob flow, persisted timing/evidence, owner-bound metadata, separate admin access and manual blocking, and rules linked to actual outcomes. `tests/docker_smoke.py` accepts `--url`, `--console-url`, `--ca` and a bounded wait timeout default10 seconds; it exits nonzero on a failed check and prints evidence IDs without secrets.
- [ ] Controller runs `& $labPy -m pytest -q`; expected no failures. Fix concrete failures via Sol diagnosis and the designated worker; broaden checks only for new changes or failures.
- [ ] Controller runs the exact Docker preparation/preflight commands below. Prove a normal HTTPS request appears in the capture before probing. Verify observed client.10/server.20 and R1 evidence for five ports.
- [ ] Controller runs the mounted independent Docker smoke script below. It submits failed logins, successful login, and foreign-record denial, then inspects the ordinary admin snapshot API for R2-R5 evidence. It verifies block/unblock from the unaffected admin website. Record actual command output and observed evidence.
- [ ] Controller stops the server cleanly, reads the saved capture with TShark, and imports it twice using the commands below. Expected: readable file, offline R1, second import inserts0 and adds no alerts or live changes. Restart the server and verify saved records, evidence and a deliberately retained block survive, then unblock that source through the admin site. No implicit reset.
- [ ] Controller opens both websites and visually verifies navigation, full copyable ciphertext/hash/signature, timestamps, sub-millisecond timing table/bars, admin polling/alerts/status, and block/unblock. Record screenshots or concrete observations in T20 report. Check LAN configuration locally; explicitly record that a complete physical two-computer test needs that hardware.
- [ ] Fresh gpt-6.1-sol reviewer receives the controller-supplied whole-project diff/files, spec/plan acceptance checklist, reports, and actual test/capture/browser evidence. Resolve material findings with one consolidated fix packet and targeted rechecks. Final COMPLETE requires acceptance evidence; unmet checks remain recorded and prevent the ready tag.

**Controller Docker/capture commands for T20** (execute only after T16-T19; these are not planning-phase commands):

```powershell
$env:LAB_SERVER_IP = '172.29.0.20'
$env:LAB_TLS_NAMES = 'localhost,127.0.0.1,172.29.0.20,server'
& $labPy -m security_lab init --renew-certificate
docker compose build
docker compose up -d
docker compose ps
docker compose exec -T client python -c "import requests; r=requests.get('https://172.29.0.20:8443/login', verify='/certs/server.crt', timeout=5); print(r.status_code); r.raise_for_status()"
docker compose exec -T client python /tools/client.py probe --host 172.29.0.20 --ports 8443,8444,8001,8002,8003
docker compose exec -T client python /tests/docker_smoke.py --url https://172.29.0.20:8443 --console-url https://172.29.0.20:8444 --ca /certs/server.crt
docker compose stop server
$labCapture = Get-ChildItem -LiteralPath 'data/captures' -Filter '*.pcapng' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
& 'C:\Program Files\Wireshark\tshark.exe' -r $labCapture.FullName -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport
& $labPy -m security_lab analyze-pcap $labCapture.FullName
& $labPy -m security_lab analyze-pcap $labCapture.FullName
docker compose up -d server
```

Inspect console capture status/evidence between preflight and probing; do not continue if capture is degraded or the harmless client connection was not observed. The explicit Windows TShark path is verified on this host; use Config.tshark_path on a different host. The smoke script uses bounded polling for new alerts instead of sleep-based assertions. A stale launcher marker after an abnormal shutdown requires inspecting the process state before removing only that marker.

**M7 final checkpoint — controller:** Run `& $labPy -m pytest -q`, relevant Docker evidence checks and `git diff --check`. Check no ignored runtime secrets/data are staged; update all durable records and then:

```powershell
git add -- attacker_tools tests/test_attacker_client.py tests/test_smoke.py tests/docker_smoke.py README.md docs/DEMO.md docs/LAN.md docs/implementation docs/RESUME.md AGENTS.md docs/superpowers/specs/2026-10-09-storage-security-design.md docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git diff --cached --stat
git commit -m 'feat(M7): deliver verified storage security lab and walkthrough'
git tag -a checkpoint/m7-ready -m 'M7 verified: delivery and durable resume history'
git status --short
git log --oneline --decorate -9
```

Stage additional verified fix paths explicitly if they changed during final review; never substitute `git add .`. Keep every checkpoint and report locally. Do not push, merge, delete history, or delete durable execution artifacts as an automatic finishing step.

## Planning checkpoint M0 (before implementation)

This phase writes documentation only. Current state is AWAITING_PLAN_REVIEW. After the controller's plan self-review, commit the amended spec, routing/recovery instructions and plan, then tag it. User has already selected delegation; ask for plan review, not another choice of execution method.

```powershell
git diff --check
git add -- AGENTS.md docs/RESUME.md docs/implementation docs/superpowers/specs/2026-10-09-storage-security-design.md docs/superpowers/plans/2026-10-09-storage-security-plan.md
git diff --cached --check
git commit -m 'docs(M0): define delegated resumable implementation plan'
git tag -a checkpoint/m0-plan -m 'M0: design contracts task routing and recovery'
git status --short
```

## Resume acceptance checklist

- [ ] Written plan reviewed by user; execution approval recorded in PROGRESS.
- [ ] Controller rechecks branch/status/tags and reads unfinished task phase before editing.
- [ ] Explicit Luna/Sol routing remains available; no silently substituted models.
- [ ] Every completed task has controller evidence and the appropriate Sol review.
- [ ] Each completed milestone has its local commit, tag and synchronized ledger/report.
- [ ] Partial tasks are resumed, completed tasks are not recreated, ignored runtime keys are preserved.
- [ ] Final record page includes crypto values and actual stored generation timings; independent console, deterministic rules, and manual blocks still match the amended spec.

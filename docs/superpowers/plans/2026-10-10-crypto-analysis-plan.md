# Administrator Cryptography Analysis Implementation Plan

> **For agentic workers:** Use the task assignments below. Steps use checkbox syntax. Controller runs commands, tests, Docker, and Git; workers edit only assigned files.

**Goal:** Add an admin-only Analysis page with AES-GCM performance, full SHA-256 property demonstrations, and AES confusion/diffusion/avalanche experiments.

**Architecture:** A standalone `security_lab.analysis` module contains pure, request-local crypto experiments and imports no database, audit, or production-keyring service. The existing console app handles admin auth, CSRF, input validation, response rendering, and no-store headers.

**Tech Stack:** Existing Flask, Python `cryptography`, pytest; no new dependencies or schema changes.

**Spec:** `docs/superpowers/specs/2026-10-10-crypto-analysis-safe-tamper-design.md`

## Global Constraints

- Safe tamper is deferred and excluded from M9.
- Inputs are UTF-8 and limited to 10,240 bytes; default sample plus temporary admin input only.
- No input/result persistence, application logging/audit, session/URL/client storage, DB/schema changes, or production-keyring use.
- Every analysis action is admin-authenticated CSRF-protected POST; responses set `Cache-Control: no-store`.
- SHA-256 uses all 32 digest bytes; each property search is capped at 10,000 candidates.
- AES-GCM uses 20 warm-ups plus 1,000 timed encryptions and decryptions, with 1,020 unique 12-byte nonces; report median and nearest-rank p95.
- AES primitive experiment uses 32 random keys, one 16-byte block, 4,096 plaintext flips, 8,192 key flips, and 32 baselines. ECB warning remains visible; it is never used for message protection.
- GPT-6.1 Sol (high, fork none) handles design/debug/review; GPT-6 Luna (medium, fork none) implements predetermined test-first tasks. One writer at a time. Controller owns all commands and Git.

## Review Focus

- UTF-8 multibyte input exactly at and over 10,240 bytes: server counts encoded bytes, not characters (route test).
- GET, missing/invalid CSRF, and non-admin access: no experiment executes (route tests).
- Search budget and complete-digest matching: deterministic injected candidate/hash source verifies bounded 10,000 attempts and full digest comparisons (unit tests).
- Nonce reuse or decryption mismatch: all 1,020 nonces are unique and all timed decryptions recover the exact bytes (unit test).
- User text reflected in HTML/errors: escape output and never echo exception details or log input (route/template tests).

## File Map

- Create `security_lab/analysis.py`: isolated experiment functions and result structures.
- Modify `security_lab/console.py`: Analysis GET and three CSRF-protected POST actions, bounded input, no-store.
- Create `security_lab/templates/console/analysis.html`; modify `security_lab/templates/console/dashboard.html` and `security_lab/static/console.css` for navigation and layout.
- Create `tests/test_analysis.py`; modify `tests/test_console_ui.py` only for shared-navigation assertion if needed.
- Modify `docs/DEMO.md`, `docs/implementation/DECISIONS.md`, `docs/implementation/PROGRESS.md`, and `docs/implementation/briefs/T22.md`; create `docs/implementation/reports/T23.md` and `T24.md`.

### Task T23: Isolated Crypto Experiments

**Worker:** GPT-6 Luna (`medium`, `fork_turns: none`), using only this task; report at `docs/implementation/reports/T23.md`.

**Files:** Create `tests/test_analysis.py`, then `security_lab/analysis.py`.

**Interfaces:** Export `MAX_INPUT_BYTES = 10240`, `aes_gcm_analysis(data: bytes) -> dict`, `sha256_analysis(data: bytes, *, candidate_limit: int = 10000) -> dict`, and `aes_primitive_analysis(data: bytes) -> dict`. Result dictionaries contain values needed by the spec; avoid raw submitted text except recovered text in AES result. Crypto module must not import console, DB, audit, or identity/keyring modules.

- [ ] Write unit tests first: sample/warmup counts, unique nonces, encrypt/decrypt equality, median/p95; all three full-digest searches and limits; AES comparison counts/output widths and finite summaries.
- [ ] Run `python -m pytest tests/test_analysis.py -q`; confirm expected failures before implementation.
- [ ] Implement the three functions in `security_lab/analysis.py` following exact workloads and labels in the spec.
- [ ] Run `python -m pytest tests/test_analysis.py -q`; report exact result without running shell commands.
- [ ] Controller reviews report and diff; runs tests; Sol reviews crypto implementation. Then controller checkpoints:

```powershell
git diff --check
git add security_lab/analysis.py tests/test_analysis.py docs/implementation/reports/T23.md docs/implementation/DECISIONS.md docs/implementation/PROGRESS.md
git diff --cached --stat
git commit -m "feat: add isolated crypto analysis experiments"
```

### Task T24: Admin Analysis Page and Demo Guide

**Worker:** GPT-6 Luna (`medium`, `fork_turns: none`), dispatched only after T23 Sol review passes; report at `docs/implementation/reports/T24.md`.

**Files:** Modify `security_lab/console.py`, `security_lab/templates/console/dashboard.html`, `security_lab/static/console.css`, `docs/DEMO.md`; create `security_lab/templates/console/analysis.html`. Add route coverage to `tests/test_analysis.py`.

**Interfaces:** Import the three T23 functions. Register `/analysis` GET and three named POST endpoints under existing `create_console_app`; enforce existing `require_login('admin')`, `check_csrf`, CSRF-token template pattern, and server-side UTF-8 byte limit. Use separate result variable per panel; set `Cache-Control: no-store` on GET/POST responses. Do not call DB, audit, or keyring from analysis routes.

- [ ] Add failing tests for admin-only GET, non-admin/anonymous denial, each POST CSRF rejection, byte-limit boundary, default sample, transient text, escaped output, no-store response, and three panel labels.
- [ ] Run `python -m pytest tests/test_analysis.py tests/test_console_ui.py -q`; confirm new route tests fail for intended missing routes.
- [ ] Implement routes/template/navigation/styles and simple Demo instructions describing metrics and limitations; no safe-tamper control or mention as implemented functionality.
- [ ] Run `python -m pytest tests/test_analysis.py tests/test_console_ui.py -q` and then `python -m pytest -q`; controller records exact outcomes.
- [ ] Sol independently reviews the integrated feature. Fix findings, rerun relevant tests, update T24 report and progress.
- [ ] Controller creates the M9 completion checkpoint only after full suite and Sol PASS:

```powershell
git diff --check
git add security_lab/console.py security_lab/analysis.py security_lab/templates/console/analysis.html security_lab/templates/console/dashboard.html security_lab/static/console.css tests/test_analysis.py tests/test_console_ui.py docs/DEMO.md docs/implementation/DECISIONS.md docs/implementation/PROGRESS.md docs/implementation/briefs/T22.md docs/implementation/reports/T23.md docs/implementation/reports/T24.md
git diff --cached --stat
git commit -m "feat: add admin cryptography analysis page"
git tag checkpoint/m9-analysis
git status --short
```

If `tests/test_console_ui.py` is unchanged, omit it from `git add`. Preserve the unrelated untracked startup-recovery report. Do not stop Docker or reset project data.

## Resumption

Resume from the first unchecked step. Verify `git status`, current branch, and `git log -1`; read this plan, T22 brief, and latest T23/T24 report. Never repeat a completed task only because an agent or account changed. A task report must state exact test commands/results, review status, changed files, and next action. `checkpoint/m9-analysis` is created only after all M9 checks pass.

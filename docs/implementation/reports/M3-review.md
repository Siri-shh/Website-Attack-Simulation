# M3 independent review

## Status: PASS (independent source review and controller verification)

Reviewer: gpt-6.1-sol, high reasoning. Read-only product review against briefs T07/T08, D20/D21/D22, the approved specification, and current source/test files. No shell commands, Git operations, tests, services, helpers, or product edits were performed. Only this review report was written. T09 templates/CSS/UI tests were deliberately not inspected while their writer was active.

Controller-supplied evidence: T07 focused check 10 passed in 8.11s; T08 focused check 7 passed in 4.25s. T06 already received PASS with 20 passing tests. These are controller outcomes, not reviewer execution.

## Finding M3-01: required error message render context is absent

Priority: medium, frozen interface mismatch. At security_lab/storage.py:32-41, _error_response supplies form, record_id, and error to storage/form.html but never supplies message. Brief T08 explicitly requires errors with message, alongside the normal form contract's optional error. Consequently denied/missing/integrity responses (403/404/409), and form-validation responses (400), do not expose the agreed message context to a consuming template. Existing test-only templates at tests/conftest.py:47 read only error, so the focused tests cannot detect this mismatch. Current displayed error strings are generic and carry no foreign content; the finding is a contract gap rather than an observed plaintext leak.

Predetermined mechanical correction: add message=message to the same _template_context call, retaining error=message and the existing template/status/form behavior. Add a narrow route test using Flask's template_rendered signal or a test-only error template that reads message, and assert the expected message and status for representative denied/missing/integrity and invalid-form cases. Do not introduce a new error template or change route interfaces. Controller verifies red then green. No new architectural decision is needed because the field is already frozen by the brief.

## T07 assessment: PASS within reviewed scope

- Auth installs only login/logout; no public signup or scenario controls. Canonical stripped/lowercase username lookup uses bound SQL while password is passed unchanged to the existing password verifier. Seeded test identities explicitly use scrypt.
- Storage/console cookie names and signing secrets are separate, with Secure, HttpOnly, SameSite=Lax, and the required 65536-byte limit. Successful login clears old session state, creates fresh independent opaque session_ref/CSRF, signs the new reference, flashes Login successful, and redirects 303. Role/credential failures clear identity and sign the attempted canonical account with null reference.
- check_csrf now rejects missing, empty, non-ASCII, or mismatched values before credentials or mutation. Valid ASCII comparison uses compare_digest. CSRF rejection preserves identity and adds no auth outcome. Logout captures/signs departing identity/reference before clearing and redirecting 303; invalid logout CSRF is covered for both roles.
- Storage admission runs before every request, normalizes request.remote_addr, ignores forwarding headers, and logs blocked_request with current account/reference only when role=user and both are nonempty strings. Wrong-role/anonymous context is null, as D21 requires. Admin admission is unaffected. Event payloads retain the fixed signed field allowlist, actual configured listener port, and null record reference.

## T08 assessment: otherwise conforms; approval waits on M3-01

- All five ordinary storage route shapes are present and protected by user auth. Saves enforce CSRF and redirect 303 to detail; no console/attack/scenario endpoints are registered.
- List/read/edit/save delegate to the frozen record services without duplicate cryptography or detector logic. Detail passes the verified stored row and owned plaintext only after successful read_record; foreign errors never render a foreign row/plaintext/evidence. Submitted text retained on rejected POST belongs to the submitter.
- RecordDenied/RecordMissing/IntegrityError map to 403/404/409. ValueError retains submitted form at 400; oversized form handling comes from shared 413 limit. Valid routes always pass username and a CSRF string. Normal list/form/detail contexts match the brief. D22 registers utc=format_utc and successful-login flash is produced by auth.
- Tests isolate config/keys/database, seed scrypt users, and install explicitly test-only DictLoader stubs. Tests cover authentication redirect, save/edit redirects, real read-service use, foreign GET/POST denial, missing IDs, CSRF, and request-size limit. UI/final render coverage remains T09's phase.

## Remaining gate

Resolve M3-01 and supply controller check results. When T09 is stable, review its actual templates/CSS/tests against brief T09 and the saved-evidence/timing specification, then reconcile this report to a final milestone verdict using controller full-suite results. Browser verification is a later acceptance task and is not claimed here.

## T09 stable-source phase: static UI PASS; two test corrections required

Controller supplied focused UI result: 2 failed, 1 passed in 2.30s. Inspected stable tests/test_storage_ui.py, all five owned storage templates, storage.css, and package-data configuration. No commands/tests or product edits were performed by the reviewer.

### M3-02: verification wording assertion does not match equivalent rendered wording

At tests/test_storage_ui.py:82 the test requires Signature verification passed. The actual template at security_lab/templates/storage/detail.html:26 correctly renders Digital signature verification passed, alongside the explicit Ed25519 digital signature label and the stored signature. The failure is a literal wording mismatch; it is not a missing signature-verification result. Predetermined correction: change only that assertion to require Digital signature verification passed. Retain the exact saved Base64 signature, ciphertext, nonce, hash, UTC times, byte counts, hash-verification result, and Ed25519 label assertions. No production wording change is required.

### M3-03: refresh comparison includes the deliberately transient login flash

At tests/test_storage_ui.py:89 login queues the required Login successful flash (D22), and the first detail GET consumes it via storage/base.html:22-28. The second GET correctly omits it. Therefore the whole-page equality at tests/test_storage_ui.py:116 fails even though cryptographic evidence and saved timing display are unchanged.

Predetermined correction: immediately after _login(real_storage_client) in test_detail_escapes_script_title_and_uses_saved_timings_without_regeneration, request / once using base_url=https://localhost; assert status 200 and that its response contains Login successful. Then retain the rest of the test unchanged: save with injected 60/20/50ns values, replace records.seal_record with the rejecting guard, issue the two detail GETs, require escaped title, exact millisecond values, saved nonce/signature, measured-version label, and complete equality of those two detail pages. This consumes the one-time flash in the normal redirected landing page and verifies D22 explicitly, while preserving the original strong refresh and no-regeneration checks. Do not remove flash rendering, suppress the login flash, drop equality, or remove the rejecting seal_record guard.

### T09 requirements checked

- All owned templates exist. List/create/edit/detail/navigation are ordinary owner operations with CSRF-backed POST logout/forms. User-supplied title/body, identity, and error/flash messages are escaped by ordinary Jinja HTML interpolation.
- Detail renders full stored ciphertext/nonce/signature Base64 and SHA-256 hexadecimal strings. Evidence CSS uses pre-wrap, overflow-wrap:anywhere, and user-select:text, with no truncation. Hash and digital signature labels/results are separate.
- Version and created/updated/generated timestamps use the registered utc filter; input/ciphertext/envelope bytes are labelled. Durations read saved ns fields, divide by 1000000, and format six decimals with ms units. The three-row numeric table and three CSS bars scale to the maximum saved duration with a denominator floor of 1, including all-zero metrics.
- The saved-version operation-measurement label and current-machine/general-benchmark/security limits are present. Templates contain no generation calls, benchmark runner, attack/scenario controls, or foreign record access path. Ownership protection remains in T08/T06; the actual-template foreign evidence test passed according to supplied UI results.
- Package data includes root/nested HTML and static CSS. The generic error.html is currently unused by T08, which preserves its frozen form-based error rendering; this does not require route changes.

Final M3 approval remains pending M3-01's message-context correction, these two bounded UI test corrections, controller focused checks and fresh full-suite result, and final review of the resulting stable files.

## Final scoped correction review

Verdict: PASS for the independent M3 source review. No unresolved material findings remain. Milestone completion still awaits the controller's fresh full-suite result; it is not claimed by this verdict.

- M3-01 resolved: security_lab/storage.py:40 now passes message=message while retaining error, form, record_id, username, CSRF, status mappings, and all route behavior. tests/test_storage.py:147-208 captures actual template context for real invalid-form 400, foreign-record 403, missing-record 404, and corrupted-record 409 responses, asserting message is present, nonempty, and equals the displayed error. Controller supplied focused green: 8 passed in 4.90s.
- M3-02 resolved: tests/test_storage_ui.py:82 now requires the actual explicit Digital signature verification passed wording. The existing saved evidence, hash result, UTC times, and bytes checks remain intact.
- M3-03 resolved: tests/test_storage_ui.py:90-92 consumes/asserts the successful-login flash on the ordinary / landing page before the refresh test. Exact 60/20/50ns-to-ms assertions, escaped title, saved nonce/signature, rejecting seal_record guard, and equality of both subsequent detail pages remain at lines 95-119. Controller supplied focused UI green: 3 passed in 1.97s. No UI production edit was needed.
- T07 remains PASS with supplied focused 10 passed in 8.11s; T06's earlier independent PASS and 20-test evidence remain recorded separately.

This final scoped pass reviewed only the authorized corrections to stable files; no worker commands, tests, Git operations, services, helpers, or product edits were performed. Browser appearance remains reserved for T20, as specified.

## Final controller verification evidence

Controller supplied fresh full suite: pytest -q --tb=short — 209 passed in 42.17s, exit 0. Controller also reports clean git diff --check and only authorized M3 code/templates/tests/documentation changes in status. The reviewer did not run these commands.

Final milestone review verdict: PASS. T06 remains covered by its separate accepted review; T07/T08/T09 source review and focused checks pass, all M3-01/M3-02/M3-03 items are resolved, and the fresh full suite passes. No material unresolved findings remain in the reviewed M3 scope. Controller may synchronize task/plan completion, milestone commit and checkpoint tag. Browser layout inspection remains the planned T20 acceptance work; no browser verification is claimed here.

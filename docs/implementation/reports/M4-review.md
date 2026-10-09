# M4 independent review

Reviewer: gpt-6.1-sol, high reasoning. Read-only product review; reviewer ran no shell, tests, Git, installations, services, or helpers.

Final result: **PASS**. F1 and prior minor findings are resolved. Controller may complete the M4 checkpoint; actual browser layout/polling acceptance remains scheduled for T20.

## Phase 1: T11 backend

Result: PASS for the T11 contract; final M4 decision awaits completed T12 and controller milestone checks.

Evidence supplied by controller: T11 console tests 7 passed in 5.98s; backend unchanged since that verification. T10 independent review PASS, 21 rule tests and 113 audit/storage regressions passed; T10 was not re-reviewed. Recovery base dcff01c600e37e124bf5b24222a2b462eaf0e611; controller supplied clean Git status before its progress update.

Reviewed AGENTS, RESUME, PROGRESS, DECISIONS, T11 brief/report, console.py, test_console.py, relevant spec/plan contracts, and existing auth/audit/database/config dependencies.

- Independent admin factory delegates to the established admin-role authentication contract, distinct console secret/cookie, and no storage admission hook. Dashboard/API and both actions require admin authentication; actions check CSRF before mutation.
- Event/alert queries bind domain, use descending time plus deterministic seq/id ties, and limit each list to 100. Explicit public allowlists omit raw signed payload/signature and secrets. UTC uses the established microsecond formatter. Audit rows are verified and expose a boolean; unsigned connection observations expose null. Default live queries exclude offline evidence, and available domains are sorted.
- Both manual actions normalize the target and commit persistent state together with signed evidence in the same transaction. Actual admin socket peer is src_ip; target is dst_ip. IP/reason validation, redirect303, and existing-session storage blocking match the contract. No automatic ban or firewall behavior was introduced.

No blocking findings. Minor cleanup: console.py:112-117 contains unused _record_block_event left from partial work; its nonexistent request.app connection and empty payload would fail if ever called. Current routes do not call it and correctly use their transaction connection. Remove this dead helper in the next bounded mechanical edit; no additional tests are needed solely for deletion. T11 report header still says TESTS_READY while its appended controller evidence says VERIFIED_PENDING_REVIEW; reconcile that header during milestone documentation update.

## Phase 2: T12 and milestone

Pending completed T12 files and controller focused/milestone command results. No unfinished T12 product/test files were inspected during phase 1.

### T12 scoped red-phase diagnosis

Controller supplied `pytest tests/test_console_ui.py -q`: five fixture setup errors in 0.26s, `console_app` not found. This is an unintended red: a fixture local to test_console.py is not automatically visible to another test module. No product implementation files were inspected or edited for this diagnosis.

Exact bounded Luna fix, only tests/test_console_ui.py: add imports `from werkzeug.security import generate_password_hash` and `from security_lab.console import create_console_app`. Change real_console_client signature to `(config, keys)`. Inside it, seed Bob user/BobPass!2026 and admin admin/AdminPass!2026 exactly as T11 with the existing transaction helper and scrypt; create `console_app = create_console_app(config, keys)`, set `console_app.config.update(TESTING=True)`, retain the existing FileSystemLoader/cache-clear/test-client lines. Do not import the sibling test module or broaden conftest.

Also repair the block-form test precondition within that test: after successful admin login, obtain `_csrf(real_console_client, "/")`, POST `/blocks` with ip192.0.2.77, reasonreviewed, csrf_token and assert303, then perform its existing dashboard GET/assertions. Its current expectation of an Unblock form without any seeded block cannot succeed with the approved empty-state behavior. Keep this setup local so the empty-state test remains empty. These are test-fixture corrections, no product/interface change. Controller reruns intended red after the bounded fixes.

### Completed T12 review: NEEDS_FIX

Controller supplied fresh required M4 suite: pytest tests/test_rules.py tests/test_console.py tests/test_console_ui.py -q --tb=short, 33 passed in 12.19s, exit0. Root supplied Git status limited to authorized M4-owned files. D26 dead helper deletion and T11 report header reconciliation were inspected and are correct; prior minor findings resolved. T10 and unchanged prior integrations were not re-reviewed or rerun by this reviewer.

Inspected completed dashboard.html, console.js, console.css, test_console_ui.py, T12 brief/report, bounded console.py cleanup, and DECISIONS. Safe server escaping and dynamic textContent cover event/account/evidence/block text; no HTML interpolation is used. Manual block/unblock forms retain ordinary POST and CSRF. Capture state/errors, empty states, network metadata limits, R1-R5 reasons/evidence, and source versus attempted/authenticated account wording match the contract. Two-second polling has an in-flight guard and preserves data on HTTP/fetch/JSON-parse failures. Actual browser layout/polling remains scheduled for T20 and is not claimed here.

**Important finding F1 — superseded domain response renders under another selected domain.** security_lab/static/console.js:117-131 captures the selector only when building the query, then unconditionally renders the asynchronous result. Reproduction by source trace: initial live refresh is pending; administrator selects an offline domain; change handler returns due to inFlight; live response resolves and renders live alerts/application events while the selector remains offline. Those tables omit row-level domain, so evidence appears under the wrong domain until another successful poll. Backend queries remain isolated; this is a presentation race requiring a bounded fix before final M4 PASS.

Exact Sol algorithm for Luna, only console.js refresh(): after setting inFlight, before try, set `const requestedDomain = domainSelect.value || "live";`; build URLSearchParams with requestedDomain. Replace `render(await response.json());` with `const data = await response.json(); if (requestedDomain === (domainSelect.value || "live")) render(data);`. In finally, clear inFlight, then `if (requestedDomain !== (domainSelect.value || "live")) refresh();`. This discards a superseded response and immediately serializes a request for the latest selection, retaining the existing no-overlap guarantee. No interface/backend/style changes required. Controller should verify one delayed response with a domain change produces no stale render and starts exactly one latest-domain follow-up, alongside the affected focused checks. Existing HTML tests do not exercise this asynchronous race; no broad T10/regression reruns are requested solely for this finding.

Final M4 PASS pending F1 fix and supplied targeted verification.

### D27 scoped re-review: final PASS

Inspected only the changed refresh() logic, new tests/console_polling.test.cjs, and recorded D27 decision. Requested domain is captured before the asynchronous fetch, superseded JSON is discarded before render, and finally releases the in-flight guard before immediately requesting the latest selection. This resolves F1 without permitting overlapping fetch/JSON lifetimes. No other previously approved contracts changed.

The dependency-free Node regression loads the actual console.js unmodified, delays both HTTP response and JSON completion, changes live to offline, exercises interval/change events while in flight, and checks no superseded marker appears, immediate latest-domain follow-up, correct offline content, and maximum one active request. Controller evidence: 1 Node test passed in 107.78ms; affected Python UI suite 5 passed in 4.82s. Earlier required M4 suite 33 passed in 12.19s, with only console.js changed subsequently. These checks satisfy the scoped fix; no redundant broad rerun is requested.

No remaining material findings. T10 prior independent PASS and supplied unchanged integration evidence remain valid. M4 final review PASS covers implemented backend/UI contracts and the scoped polling regression, without claiming the later real-browser or capture/deployment acceptance checks.

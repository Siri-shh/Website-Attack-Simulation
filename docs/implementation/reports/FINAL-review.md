# Final independent whole-project review

Reviewer: gpt-6.1-sol, high reasoning. Product review is read-only; the reviewer ran no shell commands, tests, Git, installations, services, real HTTP requests, or helpers. Only this report was written.

Final result: **PASS**. The single important F1 console integration finding is resolved, with source review, focused controller regressions and actual rebuilt Docker browser evidence recorded below. No remaining critical or important findings.

## Scope and evidence

Reviewed AGENTS.md, RESUME, PROGRESS, DECISIONS, accepted design and approved atomic plan, FINAL-review-package, M4 review, T20 report, every security_lab Python module and schema, storage/console/login templates and static assets, attacker_tools/client.py and its README, Dockerfiles/Compose/package configuration, README/DEMO/LAN, and relevant console/polling/in-process smoke tests. Established independent milestone cryptographic, rules, capture, and lifecycle reviews were trusted where unchanged; they were not exhaustively repeated.

Controller evidence, not reviewer-executed checks: existing full pytest 314 passed/1 skipped; added production-template smoke 2 passed; Windows-skipped reset directory-link safety test 1 passed on Linux; actual Docker build/init/two distinct addresses and CA-verified host/client HTTPS; real captured SYN and R1–R5; graceful stop with marker removal/readable PCAP; offline first import 94 events/1 alert and repeat 0/0; restart preserved record v2 full crypto/timings, alerts and deliberately retained block, then admin unblocked. Storage browser create/edit/full evidence/timing layout was visually inspected by controller. Root supplied actual console browser observation described in F1. Actual physical second-computer LAN verification remains unavailable and is explicitly documented.

## F1 — Packet traffic evicts signed application logs from the monitoring console

Important. Location: security_lab/console.py:58 (single shared newest-100 event query), security_lab/templates/console/dashboard.html:51 and :64 (both sections filter that same list), security_lab/static/console.js:48 (same filter after polling). Related usability: security_lab/static/console.css:36 (.table-wrap has no vertical bound).

The snapshot applies LIMIT 100 before separating connection attempts from signed application events. Ordinary console polling itself establishes real HTTPS connections, and captured packet traffic competes with the events that the administrator is supposed to monitor. Root's actual browser observation progressed from 99 network attempts/1 signed application event to 100/0 while the signed events remained persisted. An active probe/connection workload causes the same failure sooner. The page therefore advertises no signed application events despite existing login/access/block evidence. This materially fails the user's separate administrator log-monitoring requirement. It is not a detector/data-loss defect. Rendering up to 100 rows in each unbounded table also places alerts and manual controls far below the visible monitoring area.

### One bounded correction packet

1. In snapshot, query the selected domain's newest 100 connection_attempt rows and newest 100 non-connection_attempt rows independently, each ORDER BY time_us DESC, seq DESC with bound parameters. Combine the two row lists and sort by (time_us, seq) descending before the existing allowlisted/signature/UTC mapping. Retain the current events key and all event-field semantics; events may now contain at most 200 rows, with each UI section at most 100. Keep alerts at 100 and preserve domain isolation.
2. Keep real captured admin traffic. Do not hide/filter console connections, modify TShark scope, change rules, introduce pagination/components, or remove packet evidence to solve this presentation problem.
3. Give existing .table-wrap a modest fixed maximum height (for example 32rem) and overflow:auto, preserving all rows and horizontal access while keeping later evidence and manual controls reachable. No design expansion needed.
4. Controller regression: seed more than 100 newer packet observations plus valid older signed application evidence and assert both categories remain visible, each category max100, correct newest-first ordering, live/offline isolation, unchanged signature flags and public allowlists. Current console tests cover 105 application rows and only one offline packet; they do not cover mixed-source starvation. Controller reruns console/UI checks and existing Node polling regression, then checks the actual Docker browser dashboard after sustained polling and enough existing/new packet observations. Verify signed events remain present, scroll areas retain access to all rows, and alerts/manual block/unblock remain accessible.
5. Record the changed bounded snapshot contract in DECISIONS and the plan before the predetermined implementation is delegated. Scoped re-review is sufficient after the supplied controller evidence; no rerun of unchanged cryptographic/rules algorithms is requested solely for this fix.

## Resolved scope interpretation

The design's separate-console paragraph still says to display encrypted-record metadata/verification in the console. The approved T11/T12 interfaces explicitly freeze the console to capture/events/alerts/blocks; latest user steering places cryptographic values on the storage website itself and asks not to overbuild. Root supplied that correction context. Sol judgment: retain the approved console surface and owner-protected storage cryptographic evidence. Reconcile the stale spec wording in a durable D37 clarification before completion; do not add an admin record browser or decryption surface. This is a documentation alignment step, not a second product finding.

## Other integration conclusions

Separate session secrets/cookies/roles, server peer normalization, admission before storage routing, CSRF on mutations, persistent manual blocks, ownership before record evidence/decryption, encrypted title/body, canonical SHA-256/Ed25519 verification before AES-GCM decryption, signed content-free audit allowlists, persisted actual generation timings, transactional rule evaluation, isolated idempotent offline domains, certificate/key persistence, shutdown ownership/reset containment, and optional ordinary external clients match the accepted contracts. No website attack/scenario controls or automatic blocking were introduced. Documentation correctly distinguishes packet metadata from application outcomes and Docker acceptance from pending physical LAN hardware verification.

Initial review withheld PASS pending F1's bounded change, controller checks/browser evidence, durable scope reconciliation, and scoped re-review. These conditions are now satisfied as recorded in the final scoped result below.

## F1 scoped re-review — code accepted, controller verification pending

Inspected only the bounded console.py quota/merge change, .table-wrap CSS, new mixed-traffic regression and D37/D38 reconciliation. Two parameterized per-domain queries independently select the newest100 connection_attempt and newest100 other events, then merge by descending(time_us,seq); existing field/signature/UTC mapping and alert/block semantics are intact. CSS max-height32rem/overflow:auto retains all rows and both scroll directions. No capture/rule/schema/session behavior changed. D37 and the corrected spec now match the approved scope.

Controller supplied the corrected intentional regression red: 1 failed/7 deselected in2.40s due to shared-limit starvation. The earlier attempted offline signed-audit fixture correctly failed because audit payloads are live-only; controller removed that invalid fixture without changing product or scope. Existing Node polling regression passed132.54ms. Python focused and actual rebuilt Docker browser evidence remain pending; final PASS is withheld until supplied.

Controller focused green after the inspected F1 product change: tests/test_console.py + tests/test_console_ui.py + tests/test_smoke.py, 15 passed in16.97s; existing Node polling regression, 1 passed132.54ms. Actual rebuilt Docker browser retention/scroll/manual-controls observation remains pending. No further product change reported.

## F1 final scoped result — PASS

Controller supplied actual rebuilt Docker/browser evidence after the inspected bounded change: image build exit0, live capture running; dashboard retained100 network observations and39 signed application events, then43 signed events after continued polling, rather than dropping to0. The network scroll area measured512px high with4556px content and overflow:auto. Browser Block of observed client172.29.0.10 produced a real CA-verified storage403 while admin access remained available; browser Unblock restored storage200. Selecting the actual offline SHA-256 domain displayed94 packet events,0 application events and1 offline R1; switching back to Live displayed100 network events,43 signed application events,6 alerts,0 blocks and running capture. Screenshot artifact console-final-alerts.png is controller QA evidence.

Together with the inspected100/100 independent query contract, corrected regression red, focused15 passing Python checks and existing passing Node polling regression, this resolves F1 and establishes actual source-separated retention, bounded table access, domain isolation and continued manual-control behavior. D37 spec reconciliation and D38 durable plan/decision updates are complete. No broader source sweep or redundant algorithm tests were repeated. Prior whole-project review conclusions and actual crypto/capture/replay/restart acceptance remain valid.

Final whole-project review: **PASS** for the accepted implementation and demonstrated Docker delivery. Controller may complete T20/M7 and the ready checkpoint after its ordinary durable-record/Git checks. This does not claim actual two-physical-computer LAN hardware verification; that explicit delivery limitation remains.

# Final console F1 fix

Status: implementation ready for controller verification and scoped Sol review.

## Finding and change

F1 showed that the selected-domain snapshot applied one newest-100 quota before the UI separated captured connection attempts from signed application events. Newer packet rows could therefore hide every signed log. The snapshot now queries up to 100 rows per category using the selected domain and deterministic time_us DESC, seq DESC order, then merges them in time_us, seq descending order before the existing public-field and signature mapper. Each UI category remains capped at 100, alerts remain capped at 100, and the public event mapping is unchanged. The console tables now have a 32rem maximum height with scrolling while retaining horizontal overflow.

## Regression and controller evidence

tests/test_console.py adds a mixed-source regression with 130 live packet observations and 130 valid signed application events. It checks independent newest-100 category bounds, a 200-row merged snapshot in descending order, signature values, the existing field allowlist, and offline-domain isolation.

The first controller red run exposed an invalid test fixture: application audit events are permitted only in the live domain. The fixture was corrected to keep offline evidence packet-only. The next controller red run failed as expected at len(events) == 200 (actual 100), with one failure and seven deselected tests. No product edits were made before this expected red result. This worker ran no commands, tests, Git operations, or processes. Green verification and actual Docker-browser recheck remain with the controller.

Files changed: security_lab/console.py, security_lab/static/console.css, tests/test_console.py, and this report.

Controller verification: correctedF1red1failed7deselected2.40s. Greenconsole/backend/UI/inprocesssmoke15passed16.97s. ExistingNodepolling regression1passed132.54ms. ActualDocker rebuild/browserquota/scroll/controlverification pending; scopedfreshSolre-reviewpending.

Actual rebuiltDocker/browserPASS: liveattempts100 signedapplicationevents39 retained duringpolling; capture running. NetworktableclientHeight512 scrollHeight4556 overflowauto. BrowsermanualBlock.10 producesverifiedclientstorage403 whileadmincontinues; Unblock restores200. Actualdomainselectorofflinehash shows94packets/0applicationevents/1offlineR1 thenLive restores signedlogs andalerts. No new detector/schema change.

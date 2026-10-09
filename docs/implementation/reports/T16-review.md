# T16 independent review

Result: **PASS** after D32. No remaining critical or important findings.

Reviewed cli.py, __main__.py and test_cli.py against the T16 brief and D31; used prior shared-module review context. T17 deployment brief confirms the approved direct python -m security_lab serve container command. Reviewer ran no shell, tests, Git, processes or helpers and edited no implementation files.

## Resolved important finding

**SIGTERM does not enter owned shutdown** — cli.py:144–178. _serve handles KeyboardInterrupt but installs no SIGTERM handler. Normal Docker stop/down sends SIGTERM to the direct Python container command; this bypasses Python finally cleanup, or remains ignored by PID 1 until forced termination. The persisted server.pid then blocks the next startup, and owned capture/listeners are not drained.

Bounded resolution: during the main-thread serve lifetime install and restore a SIGTERM handler that requests the same graceful interruption/cleanup path. Preserve marker retention when cleanup is incomplete. Add an injected signal-handler regression proving capture/listeners stop and the owned marker is released; verify real Docker stop/restart at T20. Controller accepted this finding for D32 and one Sol fix wave.

## Remaining scope

No additional critical or important findings. Missing-only seed insertion preserves credentials, edited encrypted records and prior evidence; explicit certificate renewal delegates without replacing application keys. Two distinct threaded HTTPS listeners share the configured certificate while app secrets/cookies remain separate. Partial binding/startup cleanup closes only owned resources; non-daemon request workers and server_close drain requests before marker release. Atomic complete-JSON marker publication refuses existing valid/malformed markers and release checks file identity/content, preserving operator replacements. No recorded PID is killed. Reset requires exact confirmation, resolves/refuses root/repository/ancestor and protected Project/code targets, preflights the entire bounded deletion allowlist and capture tree before removal, rejects links/reparse points, preserves keys/unknown files and reseeds clean state. Offline CLI delegates without live capture/listeners.

Controller pre-fix evidence: CLI tests **27 passed, 1 skipped in 18.20s**. Skip is Windows directory-link creation privilege; Linux verification remains later. Tests inject serving resources; real Linux signal and request-drain behavior are not yet claimed. That pre-fix gate is resolved by D32 below.

## D32 final re-review

Reviewed the bounded SIGTERM context and its regression. main wraps the complete serve lifetime, before marker/init/listener/capture startup, with a main-thread SIGTERM handler that raises KeyboardInterrupt into the existing cleanup; the prior handler is restored after cleanup. The injected handler regression verifies owned capture/listener shutdown, marker release and restoration. Controller full CLI green: **28 passed, 1 skipped in 18.64s**. The Windows directory-link privilege skip remains explicit. Lifecycle integration approved. Actual Docker SIGTERM stop/restart and Linux request-drain behavior remain T20 checks.

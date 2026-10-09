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

Append later entries with task ID, decision, reason, and effect on the contracts. Resolve ambiguities using the user requirements and spec before changing the plan.

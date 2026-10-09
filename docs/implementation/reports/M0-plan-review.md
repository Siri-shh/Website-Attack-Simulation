# M0 planning self-review

Status: documentation prepared; product implementation awaits user plan review.

## Requirements coverage

| Requirement | Tasks / durable record |
| --- | --- |
| Separate storage and admin websites | T07-T12, T16 |
| Owner-only records, confidentiality/authentication | T03-T09 |
| Ciphertext/hash/signature/timestamps on storage website | T04, T06, T08-T09 |
| Actual encryption/hash/signing generation timings | T04 deterministic timer tests, T09 owner UI |
| Integrity and accountability | T04-T06, T10-T11 |
| Predefined R1-R5, flagging, manual block/unblock | T10-T12 |
| Live traffic and PCAP with Wireshark/TShark | T13-T15, T20 |
| Docker two devices, physical LAN fallback | T16-T17, T19-T20 |
| Independent external attacker convenience scripts | T18 |
| Persistent data and explicit reset | T02, T16, T20 |
| Atomic task model assignments | All T01-T20; AGENTS.md |
| Controller-only CLI/tests/Git | AGENTS, task protocol, checkpoint commands |
| Local history after each milestone | Exact commit/tag commands M0-M7 |
| Token/account recovery | RESUME, PROGRESS, DECISIONS, tracked reports, preserved .git |

## Interface and step checks performed by controller

- Checked all 20 task IDs against the progress table and dependency order. Earlier tasks provide later consumers' config, keys, schema, crypto, event, record, auth, rule and packet contracts.
- Checked shared-file handoffs: conftest additions belong to their task; T10 explicitly modifies audit to add atomic evaluation; T08's temporary test templates do not require future T09 files; T17 mounts the future smoke script directory for T20.
- Fixed a metadata integrity omission in list_records by adding source/session parameters so corrupt owned records can be audited before errors reach routes.
- Fixed separation of console login events from storage R2/R3 and specified block audit source versus target addresses.
- Specified CSRF field and template context names, status/redirect codes, event domain separation, input byte counts, exact timer boundaries, and malformed packet handling.
- Checked all five Review Focus classes have owning task checks. Tests assert behavior, boundary values, cryptographic failure, actual blocking, and idempotence rather than simply matching implementation constants.
- Checked all milestone Git commands use explicit project paths and never stage runtime data/keys or reset history. Recovery WIP commits are marked incomplete and do not receive milestone tags.
- Checked account recovery relies on local tracked documents and actual Git state, not plugin scratch state or vanished agent identities. No durable ledger deletion occurs.
- Fixed unfounded package-version assumptions by using declared compatibility floors and requiring actual dependency locking during M1.

## Verification performed at planning stage

Controller read the amended spec, plan and recovery instructions; checked task/ledger/tag inventories and document references; ran `git diff --check`. No product tests, Docker build, website, cryptographic performance measurements, or physical LAN verification have been run because product code has not been implemented.

Official documentation was fetched through Context7 for Flask application factories/session isolation, Werkzeug scrypt password hashing, cryptography certificate generation, and the earlier AES-GCM/Ed25519/TShark contracts. Reasoning agents used GPT-6.1 Sol; accepted decisions are in DECISIONS, with conflicting suggestions explicitly rejected there.

Remaining gate: user review of the written implementation plan. The selected execution method is already delegated Luna/Sol; do not ask the user to choose it again.

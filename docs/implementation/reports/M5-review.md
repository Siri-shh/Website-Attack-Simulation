# M5 independent review

Result: **PASS** for T13, T14 and T15. No critical or important findings.

Reviewed packets.py, capture.py, pcap.py and their tests against the frozen task briefs and D24/D29/D30; inspected transaction, schema and rule APIs for integration. Reviewer performed no shell commands, tests, Git operations, process launches or code edits.

- T13: exact field order, Decimal microseconds, IPv4/IPv6 normalization, configured-server incoming SYN-without-ACK filtering, capture/frame references, persisted capture/flow/sequence deduplication and atomic insertion/R1 evaluation satisfy the contract. Packet evidence remains unsigned and contains no inferred application outcomes.
- T14: start/stop serialize ownership; no restart replaces unreaped resources. Separate bounded stdout/stderr readers and exit supervisor preserve idle-running semantics and report failures. Malformed rows continue ingestion; timestamp regression warns while retaining original times. Stop waits, escalates to kill, joins only owned threads, retains capture files and reports incomplete shutdown without releasing ownership. The five-field status persists under capture. Lifecycle approved before launcher integration.
- T15: streamed SHA-256 defines offline domain/capture identity; shared fields and literal argv avoid shell interpretation. Decoder/row validation and stable-file rehash precede writes; accepted events sort by original time/frame. Replay is idempotent, alert_count reports newly added alerts, R1 remains packet-only and live evidence/status/blocks remain isolated. Recoverable per-event transactions are consistent with the approved insertion contract.

Controller evidence supplied for this review: packet tests **11 passed in 0.49s**; capture tests **9 passed in 2.29s**; offline tests **6 passed in 1.40s**. These use simulated TShark output/processes. Actual simultaneous TShark save/fields compatibility and real PCAP readability remain the documented T20 acceptance checks; this review does not claim real capture verification.

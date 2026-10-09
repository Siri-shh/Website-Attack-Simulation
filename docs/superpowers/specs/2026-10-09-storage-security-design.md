# Storage website and live network security console

## Purpose and agreed scope

Build a small, understandable security project in `new_project` for a professor demonstration. Bob logs into a realistic storage website and creates or edits his own text records. An administrator monitors a separate website while manual actions or external Python tools send real requests to the storage service.

Demonstrate confidentiality, integrity, authentication, and accountability. Use actual traffic capture and PCAP analysis through Wireshark's TShark. Docker is the primary two-device setup; two physical computers on the same LAN are the fallback.

The storage website always enforces security. It has no attack controls, scenario selection, or vulnerability switch. Its normal record detail page includes the owner's cryptographic evidence and measured generation timings. The project does not depend on an attacker declaring a scenario or reporting an attack. External scripts are conveniences for the presenter acting as the attacker, rather than a service or component of the security framework.

## Architecture

- One small Python package using Flask, SQLite, and `cryptography`, with ordinary server-rendered HTML and a little JavaScript for console polling.
- Two independent Flask applications/listeners: the storage website and the administrator console. They have separate addresses, authentication sessions, cookie names, and session signing secrets. The console is not a route in the storage website.
- A small background worker runs TShark, saves packet captures, and feeds observed connection metadata to the detector. A shared SQLite database stores records, signed audit events, network observations, alerts, and manual IP blocks.
- No separate frontend build, Streamlit application, message broker, AI detection, or external database is needed.
- Console polling runs every two seconds. Application alerts are available at the next refresh; packet visibility also depends on capture delivery and processing. Show a visible capture status and errors.

Proposed modules: application factories/routes, database access, record cryptography, audit logging, deterministic rules, packet capture/parser, and launch/configuration. Keep their responsibilities explicit and files small. Reuse relevant old rules and concepts selectively, rather than copying the previous orchestration and UI.

## Storage website

Seed Bob and Alice as storage users and a separate administrator identity for the console. Document demo credentials. Public registration is outside scope.

Users log in, log out, list their records, create a record with a title and text, view a record, and edit their own records. Store the latest version only. Creation and edits are audited. Authentication is required for record operations, and ownership is checked on the server for every record request.

On each owner's record detail page, display the complete ciphertext as Base64, nonce, SHA-256 envelope hash as hexadecimal, Ed25519 signature as Base64, signature/hash verification results, record version, creation/update timestamps, and the time those values were generated. Clearly label the SHA-256 hash and Ed25519 digital signature separately; SHA-256 alone is not a digital signature. Do not expose password hashes, private keys, or another user's record evidence.

Show measured encryption, SHA-256 hashing, and signing generation durations for the saved version, in milliseconds, plus the encrypted input size in bytes. Measure the actual operations with a monotonic high-resolution timer; exclude database, HTTP, and HTML work. Persist the observations with their record version so refreshes show that version's measurements instead of regenerating them. Display a small comparison of encryption/hash/signing durations, with numeric values and units. Mark them as individual operation measurements on the current machine, not a general benchmark or proof of security. Measure no repeated synthetic benchmark workload on page load.

Password storage uses a salted password hashing function. SQL uses bound parameters; templates escape text. State-changing forms use CSRF protection. Sessions are cleared and renewed at login and cleared at logout. No passwords, session cookies, record plaintext, or private keys appear in audit logs or console views.

## Cryptography and accountability

HTTPS protects credentials and content in transit. Generate a persistent lab certificate with the configured server names/IP addresses, and document browser trust and attacker-tool certificate verification for Docker and LAN setups.

Encrypt both record title and text using AES-256-GCM and a fresh 12-byte nonce for each creation or edit. Authenticate the record ID, owner, and version as associated data. Store ciphertext and its authentication tag, rather than plaintext, in SQLite.

Create a canonical envelope binding the record ID, owner, version, nonce, and ciphertext. Store its SHA-256 digest and Ed25519 signature. Check the envelope hash and digital signature before decryption, and reject records that fail verification. A hash alone is not treated as proof of authenticity. Log integrity failures without revealing content.

Keep persistent encryption, signing, and session keys outside the database and source control. Signing keys attest to the server's record/audit evidence; do not describe them as a user's personal signature or proof of user nonrepudiation.

Sign canonical application audit events. Record timestamp, event ID, observed source address, attempted username or authenticated account as appropriate, action, record reference where applicable, and outcome. Verify signed events when inspecting evidence. Persistent logs provide accountability, with the stated limit that an administrator controlling the server and its keys also controls the evidence store.

## Separate administrator console

Require administrator login. Ordinary storage users cannot authenticate to the console.

Show capture health, recent network connections, application events, alerts and their evidence, flagged source addresses/accounts, and the current block list. Refresh automatically approximately every two seconds without replacing the whole page.

Show observed addresses and relevant usernames separately. An attempted username does not identify the person sending a request. Record cryptographic values and verification results are owner-protected on the storage website; the console displays signed application and network evidence without users' record content (D37).

For a flagged source, offer explicit Block and Unblock actions with CSRF protection. A block denies subsequent requests from that address to the storage website, including requests carrying an already authenticated session. Denied requests are logged. Blocks persist across restarts. These are application access blocks, not operating-system firewall rules: packet capture can still observe a blocked source scanning ports.

Use the actual peer address supplied by the server, never an arbitrary client forwarding header. Normalize addresses consistently. Explain that NAT can make several clients share an observed address, so the admin can inspect evidence before blocking. Console access is not subject to the storage block list.

## Deterministic detection rules

Rules depend on observed packet or application events, never scenario names or script reports. Retain the approved thresholds from the old project.

| Rule | Trigger | Evidence |
| --- | --- | --- |
| R1 Port probing | One source contacts at least 5 distinct ports on the server within 30 seconds | Captured TCP connection attempts |
| R2 Repeated failures | At least 5 failed logins for the same source and attempted username within 60 seconds | Signed application events |
| R3 Suspicious success | Successful login for that source and username within 120 seconds after R2 | Failure alert and signed login-success event |
| R4 Unauthorized access | An authenticated user requests an existing record owned by another user | Signed denied-access event |
| R5 Linked activity | R2 followed by R3, then R4 in the resulting session within 300 seconds of the login | Linked alerts and signed access evidence |

R1 and R2 emit when their threshold is crossed, suppressing repeated alerts while the condition remains active. R3, R4, and R5 retain the specific event IDs supporting each finding. Restore recent detection state after restarts so restarting does not silently erase an active window.

The rules flag suspicious behavior; they do not automatically block, declare an account compromised, or claim to detect every attack. R4 distinguishes an attempted access violation from a disclosure: the enforced website denies it.

## Traffic capture and PCAP analysis

Capture on the server-facing interface, including attempts to closed server ports. TCP SYN observations supply source/destination addresses, ports, and timestamps. Deduplicate repeated SYNs where required so retransmissions do not inflate observations. Preserve packet evidence references and save captures in a format Wireshark can open.

Use TShark for both live observation and reading saved captures, sharing the packet-normalization logic. Support an offline PCAP analysis command with results distinguishable from the current live session. Reprocessing the same capture must not duplicate findings.

HTTPS packet captures provide network metadata. Login results, account identities, ownership decisions, and integrity failures come from application audit events. The console labels each evidence source and does not claim that encrypted requests were read from PCAP.

Capture startup must be checked with a harmless request before the walkthrough. If capture fails, the console displays degraded monitoring rather than claiming that no attacks occurred.

## Two-device deployment

### Docker primary

Two containers have separate IP addresses on a private bridge network: a server device running the two websites and monitoring worker, and a client device providing a Python environment for external attacker tools. Capture inside the server namespace so traffic between containers is visible. Persist database, keys, and PCAPs in the project data directory.

Expose the two websites on separate localhost HTTPS ports. The host browser remains an ordinary additional client; display its actual observed address instead of pretending that browser requests came from the attacker container. The client container sends real traffic from its own address to the server and establishes the two simulated devices.

### Two physical computers on one LAN

Computer A runs the same storage website, console, SQLite, and capture worker. Computer B uses a browser or Python tools against A's LAN address. Configure the bind address, server address, certificate names, and capture interface without code changes. Restrict capture/detection to the configured server; do not scan unrelated LAN devices.

Document Windows interface selection and the required server ports. Use the installed Wireshark/TShark for Windows capture; account for the permissions needed by the actual capture installation. Keep the console on a separate address/port and require its administrator login.

## External attacker tools

Provide a small, separate `attacker_tools` folder as presentation conveniences. Tools accept an explicit target, credentials or candidate passwords, record ID where relevant, and bounded request counts. They make real HTTPS or TCP requests and print actual responses. They can authenticate through the same login flow as a browser.

Do not register these tools with the detector, provide attack endpoints, launch them from either website, or require a fixed five-attack progression. The presenter chooses the malicious requests. Rule evaluation works identically for manual activity and external tooling.

## Persistence, reset, and walkthrough

Records, logs, captures, alerts, and manual blocks survive ordinary restarts. An explicit reset command recreates the starting lab state and seeded accounts; it requires deliberate invocation and clearly identifies the data it resets. Never reset on page load or ordinary startup.

Provide a short README with Docker startup, separate website addresses, credentials, normal Bob record use, external tool examples, live console interpretation, manual block/unblock, saved-PCAP analysis, and the two-computer LAN fallback. Explain each security goal with the evidence the professor can inspect.

## Verification and acceptance

- Bob can create, read, and edit his records. Alice cannot read or edit them by changing a URL or request. Unauthenticated access is denied.
- Stored records contain encrypted title/text; passwords are hashed. Valid records verify and decrypt, while altered ciphertext or owner metadata is rejected and logged.
- The owner's record page displays full ciphertext, SHA-256 hash, Ed25519 signature, nonce, timestamps, version, verification results, and actual saved encryption/hash/signing timings with input bytes. Evidence is ownership-protected; refreshing does not rerun generation or replace timing values. Deterministic timer tests verify instrumentation without assuming particular real-world speeds.
- Admin login is isolated from user login; user cookies do not authorize console access. State-changing requests require CSRF tokens.
- Real connection probes and login/access attempts trigger R1-R5 according to the exact windows, including tests below thresholds and for different sources/accounts. Findings contain reproducible evidence references.
- Manual blocking denies subsequent storage requests and unblocking restores access. Spoofed forwarding headers cannot bypass a block or frame another IP.
- Logs and blocks survive a restart. Reset recreates the documented lab state.
- A Docker smoke test confirms distinct client/server addresses, successful normal HTTPS use, application alerts, captured scan evidence, and a PCAP readable by TShark.
- Verify both website layouts in a browser. Test the configurable LAN launch/capture path locally; an actual second physical computer remains necessary to verify the full physical setup.

## Documentation sources checked

- `cryptography` documentation via Context7: AESGCM with 256-bit keys, unique nonces, associated data, and Ed25519 signing/verification.
- Wireshark documentation via Context7 and installed TShark 4.6.9 help: live and saved capture support, field output, PCAPNG output, and output flushing.
- Existing project README, detection configuration, rules, target authentication code, and Compose topology.

## Implementation and recovery requirements

The implementation plan must freeze file responsibilities, interfaces, algorithms, assertions, and acceptance commands before delegating mechanical tasks to `gpt-6-luna`. Assign architecture, unresolved decisions, complex code, debugging, and reviews to `gpt-6.1-sol`. Always specify the model and reasoning effort explicitly. The main/controller agent owns installations, command-line tests, processes, capture permissions, and every Git command; subagents edit or reason from supplied task packets and do not run shell/Git commands or spawn helpers.

Define atomic tasks with dependencies, owned files, exact outputs, and completion evidence. Each milestone ends with an explicit local Git commit and named checkpoint tag after verification and review. Keep a committed progress ledger, decision log, task reports, and resume instructions in the repository. These records must survive context loss, an account change, and the disappearance of old agent identities or plugin installations. Never delete the durable recovery record at completion. Resume from verified commits and unfinished steps rather than rebuilding completed work.

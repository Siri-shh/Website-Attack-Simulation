# Code guide

When asked where a feature lives, start with these files. The main application code is in `security_lab/`.

| Feature | Where to look |
| --- | --- |
| AES-256 record encryption and decryption | `security_lab/crypto.py` — `seal_record()` encrypts; `open_record()` verifies and decrypts. |
| Image validation and image encryption | `security_lab/images.py` validates PNG/JPEG uploads and size; `security_lab/crypto.py` seals image bytes separately from text and verifies image evidence. |
| Record hash, signature, and measured reads | `security_lab/crypto.py` — `seal_record()` creates the SHA-256 hash and Ed25519 signature; verified open paths check them and report transient decryption/verification timings. |
| Login and access checks | `security_lab/auth.py` — `configure_auth()` sets up login and role checks. `security_lab/cli.py` creates the demo accounts and password hashes. |
| Save, read, edit, image actions, and version history | `security_lab/records.py` — `save_record()`, `read_record()`, and `read_record_history()` manage versioned image evidence. Owner-only preview and ciphertext routes are in `security_lab/storage.py`. |
| Signed activity logs | `security_lab/audit.py` — `append_app_event()` writes a signed event; `verify_app_event()` checks it. Login events are recorded from `security_lab/auth.py`. |
| Live traffic capture | `security_lab/capture.py` — `CaptureWorker` captures network traffic. `security_lab/packets.py` parses and stores packet observations. |
| PCAP file analysis | `security_lab/pcap.py` — `analyze_pcap()` reads a saved capture using TShark/Wireshark tools. Tests are in `tests/test_pcap.py` and `tests/test_packets.py`. |
| Hard-coded detection rules | `security_lab/rules.py` — the descriptions and logic for rules R1–R5 are here. `evaluate_event()` checks events; `_emit()` saves an alert when a rule matches. Tests are in `tests/test_rules.py`. |
| Admin monitoring and manual IP blocks | `security_lab/console.py` — `snapshot()` supplies the console data and routes handle block/unblock. The page is `security_lab/templates/console/dashboard.html`. |
| R2 storage sign-in restriction | `security_lab/auth.py` checks the live R2 IP/normalized-username pair and records restricted attempts; `security_lab/console.py` supplies expiry data to the console. |
| Crypto analysis and synthetic size sweep | `security_lab/analysis.py` contains isolated experiments and measurements; `security_lab/console.py` connects them to the admin page `security_lab/templates/console/analysis.html`. |
| Record measurement graphs | `security_lab/templates/storage/detail.html` renders graphs from saved version timings and separate current-read observations; record read wiring is in `security_lab/storage.py`. |
| Attacker client commands | `attacker_tools/client.py` — supports login attempts, record requests, and port probes. They are independent client requests, not buttons inside the websites. |

## Quick orientation

- `security_lab/` — application code, templates, and browser CSS/JavaScript.
- `tests/` — automated tests. The closest test file usually shares the feature name, such as `test_rules.py` for detection rules.
- `attacker_tools/` — optional client scripts used to send requests to the website.
- `docs/` — setup, LAN, demo, and project notes.
- `compose.yaml` — Docker services. `Dockerfile` builds the server; `Dockerfile.client` builds the client container.
- `data/` — local database, keys, certificates, and packet captures. This is runtime data, not source code; keep it private and do not delete it when cleaning the project.

For a demonstration, a useful path is: `storage.py` (website and owner-only image routes) → `records.py` (record/version operations) → `images.py` and `crypto.py` (image validation, encryption, and evidence). For R2, follow `auth.py` (login decision and temporary restriction) → `audit.py`/`rules.py` (signed outcomes and alert) → `console.py` (expiry display). For other detection, follow `capture.py` or `auth.py` → `packets.py` or `audit.py` → `rules.py` → `console.py` (alerts shown to the admin).

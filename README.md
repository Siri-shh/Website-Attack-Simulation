# Storage security lab

A two-device HTTPS lab for encrypted records and network/security evidence. The storage site enforces ownership; the separate admin site displays capture metadata and signed application outcomes. Attack helpers are optional ordinary clients.

## Docker quickstart

From this directory in PowerShell:

```powershell
docker compose build
docker compose run --rm --no-deps server python -m security_lab init
docker compose up -d
docker compose ps
```

Initialization creates missing demo data, persistent keys, and the TLS certificate. It preserves existing records. On first use, trust `data/keys/server.crt` in the browser or open the URLs and accept the lab certificate warning. Client tools verify TLS with that same public certificate.

- Storage: https://localhost:8443
- Admin console: https://localhost:8444

Demo accounts: `bob / BobDemo!2026`, `alice / AliceDemo!2026`, and console administrator `admin / AdminDemo!2026`. These are public lab defaults; never reuse them elsewhere.

## Local Windows quickstart

For a local run without Docker, use PowerShell from the project directory:

```powershell
py -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps -e .
python -m security_lab init
python -m security_lab serve
```

This uses the default localhost addresses: https://127.0.0.1:8443 for storage and https://127.0.0.1:8444 for the admin console. Trust the lab certificate at `data/keys/server.crt` when prompted. This local quickstart leaves LAN binding and capture-interface configuration at their defaults; use the LAN guide to configure a physical two-device setup. Stop the server with Ctrl+C.

## Normal record walkthrough

Sign in as Bob at the storage URL. Create a record with a title and text, save it, reopen it, and edit it. The owner detail page shows the full Base64 ciphertext, nonce, version, UTC timestamps, SHA-256 envelope hash, Ed25519 digital signature, and verification results. It also shows saved-version input bytes and measured encryption, hash, and signing durations. Refreshing displays the stored values; these are individual operation timings on this machine, not a general benchmark. Bob's record evidence is owner-protected.

SHA-256 is a digest used to detect changes; the Ed25519 signature verifies the server-signed envelope. A hash by itself is not a digital signature. HTTPS protects request contents in transit. A packet capture can show addresses, ports, timing, and encrypted traffic metadata; the signed application events show outcomes such as login success or denied record access.

## Capture and optional external clients

Check the admin console's capture status and make one ordinary storage request before a demonstration. The console should show capture running and observed traffic. A degraded capture means network evidence is unavailable.

The independent helper accepts only the explicit host/ports/record supplied. The Docker bridge permits container outbound connections; published host ports remain bound to localhost only. Examples run from the client container:

```powershell
docker compose exec client python /tools/client.py probe --host 172.29.0.20 --ports 8443,8444,8001,8002,8003
docker compose exec client python /tools/client.py request-record --url https://172.29.0.20:8443 --username bob --password 'BobDemo!2026' --record-id 00000000000000000000000000000001 --ca /certs/server.crt
docker compose exec client python /tools/client.py request-record --url https://172.29.0.20:8443 --username bob --password 'BobDemo!2026' --record-id 00000000000000000000000000000002 --ca /certs/server.crt
```

For bounded login attempts, create an untracked candidate file outside the repository and make it available inside the client container at `/tmp/candidates.txt`. Then run:

```powershell
docker compose exec client python /tools/client.py login-attempts --url https://172.29.0.20:8443 --username bob --password-file /tmp/candidates.txt --limit 5 --ca /certs/server.crt
```

The foreign-record example should return HTTP 403: R4 records a denied access attempt, and Alice's record is not disclosed. This optional request does not form a required sequence. Candidates are tried in file order, at most five by default; output does not print passwords. Do not commit candidate files or use real credentials. These tools send ordinary requests; neither website launches them or requires a fixed sequence.

## Console evidence and manual blocks

Sign in separately at the admin URL. Review capture health, observed network connections, signed application events, rule alerts, and their evidence. R1 needs at least five distinct server ports within 30 seconds. R2 needs five failed logins for the same source and username within 60 seconds. R3 needs a success for that pair within 120 seconds after R2. R4 is an authenticated denial for another user's existing record. R5 links R2, R3, then R4 in that login session within 300 seconds of success. Rules flag evidence; they do not automatically block clients. Use the console's explicit Block and Unblock controls to manage storage access. Blocks affect storage admission, not the OS firewall. NAT may make several clients appear as one source.

## PCAP analysis, restart, and reset

Stop the server cleanly so the capture file is flushed. In PowerShell, select the actual capture filename shown in `data/captures`:

```powershell
docker compose stop server
docker compose run --rm --no-deps server python -m security_lab analyze-pcap /app/data/captures/<capture-name>.pcapng
docker compose up -d
```

The offline result is marked separately from live monitoring; importing the same capture again adds zero duplicate observations/alerts. Replace the placeholder with a real filename.

An ordinary `docker compose stop server` and `docker compose up -d` preserve records, keys, captures, alerts, and blocks. To intentionally return to seeded records, first stop the server, then run:

```powershell
docker compose stop server
docker compose run --rm --no-deps server python -m security_lab reset --confirm RESET
docker compose up -d
```

Reset clears the database and captures and recreates the demo state; existing key files remain. Do not reset while the server is running.

For two physical computers on one LAN, follow [the LAN guide](docs/LAN.md). The second-computer setup has not yet had a physical hardware smoke test. Preserve the whole checkout, including `.git`, for recovery and history. Runtime keys and database/capture data are ignored by Git and must be preserved separately if needed. Project decisions, progress, task reports, and recovery steps are recorded in `docs/implementation/`, `docs/RESUME.md`, and `AGENTS.md`.

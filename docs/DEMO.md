# Short demonstration

## 1. Start and establish normal use

From the project directory in PowerShell:

```powershell
docker compose build
docker compose run --rm --no-deps server python -m security_lab init
docker compose up -d
```

Wait for the server health check. Open https://localhost:8443 and https://localhost:8444, trusting the lab certificate `data/keys/server.crt` if prompted. Make a harmless request to the storage site and confirm the admin console reports capture running and shows the connection.

At the storage site, sign in as `bob / BobDemo!2026`, create a record, reopen it, then edit it. Inspect the owner's detail page: full ciphertext and nonce, SHA-256 hash, Ed25519 signature, verification results, version, IST creation/update times, input bytes, and saved encryption/hash/signing durations. Refresh and confirm the saved evidence and timings persist. A hash detects changes; the Ed25519 signature verifies signed evidence. Each save appears in version history; expand earlier versions to compare their ciphertext, hash, signature, and timings. Older texts remain encrypted and visible only to the owner.

## 2. Use independent client requests if desired

Examples are optional and independent. They create ordinary traffic and do not activate a named scenario:

```powershell
docker compose exec client python /tools/client.py probe --host 172.29.0.20 --ports 8443,8444,8001,8002,8003
docker compose exec client python /tools/client.py request-record --url https://172.29.0.20:8443 --username bob --password 'BobDemo!2026' --record-id 00000000000000000000000000000001 --ca /certs/server.crt
docker compose exec client python /tools/client.py request-record --url https://172.29.0.20:8443 --username bob --password 'BobDemo!2026' --record-id 00000000000000000000000000000002 --ca /certs/server.crt
```

The Alice-record request is an optional foreign-record check: expect HTTP 403 and an R4 denial, with no disclosure of Alice's record. It is an independent request, not a mandatory sequence. Use the separately documented `login-attempts` subcommand only with an untracked candidate file available to the container. It stops on success or a block and never echoes the candidates.

## 3. Read the evidence

At https://localhost:8444, log in as `admin / AdminDemo!2026`. Explain that packet capture provides source/destination, ports, timing, and encrypted HTTPS metadata. Signed application events provide login and record-access outcomes. An observed username is an application value, not proof of the network sender's identity.

R1 is five distinct destination ports in 30 seconds; R2 is five failed logins for one source and username in 60 seconds; R3 is their successful login within 120 seconds; R4 is an authenticated denial for an existing record owned by someone else; R5 links that R2/R3 to R4 in the same session within 300 seconds of success. No rule blocks automatically. Use Block and Unblock manually and observe that a block denies storage requests while the separate console remains accessible.

Security-goal evidence to point out:

| Goal | Inspect |
| --- | --- |
| Confidentiality | Stored title/text are AES-GCM ciphertext; HTTPS protects traffic in transit. |
| Integrity | Owner page verifies the envelope hash and Ed25519 signature before content is accepted. |
| Authentication and authorization | Login and owner-only record routes; Alice cannot access Bob's existing record. |
| Accountability | Signed application events and rule evidence, alongside actual captured network metadata. |

Timings are saved measurements of individual operations for this version on this machine. They are not a benchmark. The server signing key attests to lab evidence; it is not a user's personal signature or proof of nonrepudiation.

## 4. Run the cryptography analysis

Sign in to the administrator console and open **Analysis**. The page offers separate AES-GCM, SHA-256, and single-block AES primitive demonstrations. Leave the input empty to use the built-in sample, or enter temporary text up to 10,240 UTF-8 bytes. The server processes each request in memory; inputs and results are not saved. The page explains the bounded-search limits, local timing scope, ECB limitation, and empirical nature of the avalanche observations.

## 5. Preserve and inspect a capture

Stop cleanly, analyze the actual filename from `data/captures`, then restart:

```powershell
docker compose stop server
docker compose run --rm --no-deps server python -m security_lab analyze-pcap /app/data/captures/<capture-name>.pcapng
docker compose up -d
```

Offline findings are labelled separately. A repeated import adds zero duplicate observations/alerts and does not change live capture status. Ordinary stop/start preserves records, keys, captures, alerts, and blocks. Keep the entire project checkout including .git for recovery; preserve ignored runtime keys and data separately if they must survive moving or replacing the checkout. Reset is an explicit action: stop the server, run `docker compose run --rm --no-deps server python -m security_lab reset --confirm RESET`, then start it again. Reset clears database and captures but preserves keys.
# Displayed times

Website timestamps are shown in IST (UTC+05:30). Stored timestamps and signed UTC values remain unchanged.

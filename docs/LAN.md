# Two-computer LAN setup

The Docker deployment uses a normal bridge network at 172.29.0.0/24, which permits container outbound connections; published host ports remain bound to localhost only. This fallback uses two physical devices on the same LAN. Computer A runs the server, storage site, admin console, database, and capture worker. Computer B uses a browser or the optional Python client. Restrict tests to A; do not scan other LAN devices. This configuration has not yet had a two-computer hardware smoke test.

## Computer A: select interface and configure

Install Python 3.11+ and Wireshark/TShark. In PowerShell, list capture interfaces:

```powershell
tshark -D
```

Choose the interface ID/name that receives B's traffic. Capture permissions depend on the installed Wireshark/Npcap configuration; verify TShark can capture on that selected interface before the walkthrough.

Set A's actual reachable LAN IPv4 address below. Include the DNS names or IP addresses B will use in the certificate names. Bind the server to all interfaces, while keeping the advertised IP and certificate SANs specific to A:

```powershell
docker compose stop server
$env:LAB_BIND_HOST = '0.0.0.0'
$env:LAB_SERVER_IP = '192.168.1.50'
$env:LAB_TLS_NAMES = '192.168.1.50'
$env:LAB_CAPTURE_INTERFACE = 'Wi-Fi'
py -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps -e .
python -m security_lab init --renew-certificate
python -m security_lab serve
```

Replace the example IP and interface. If switching this checkout from Docker, stop its server first as shown; run LAN commands in the same PowerShell session so environment values are inherited. If B connects using a DNS name, include that name in `LAB_TLS_NAMES` as well. Renew the certificate after setting final LAN names and before starting `serve`. This replaces existing Docker certificate SANs with LAN names and renews only the certificate with `python -m security_lab init --renew-certificate`; key files and encrypted records are retained. Keep these environment settings in effect for both commands.

## Computer B: trust the public certificate and connect

Copy only Computer A's public `data/keys/server.crt` file to B through a trusted means. Never copy the private certificate key, encryption key, signing key, session secrets, database, or runtime data. Install/import the certificate as trusted on B, or use it as the CA for Python requests; tools do not disable TLS verification.

- Storage: `https://192.168.1.50:8443`
- Admin console: `https://192.168.1.50:8444`

Use lab logins `bob / BobDemo!2026` for storage and `admin / AdminDemo!2026` for the console. Restrict the inbound firewall rules on A to the trusted LAN and necessary client hosts, opening TCP 8443 (storage) and TCP 8444 (admin) only. Require the admin login even on the LAN. The observed source may be a NAT/router address shared by several users; inspect evidence before manually blocking an IP.

A client example after installing the project Python dependencies on B, assuming the certificate file is `server.crt`:

```powershell
python attacker_tools/client.py request-record --url https://192.168.1.50:8443 --username bob --password 'BobDemo!2026' --record-id 00000000000000000000000000000001 --ca server.crt
```

## Verify and limitations

On A, confirm the selected capture interface is active and a normal request from B appears in the console. Confirm the source address shown matches the actual path (NAT can alter it). A's admin console remains a separate HTTPS listener. Capture concerns only A's configured interface and evidence for this lab server.

If changing A's address or certificate names, stop Docker before starting the LAN listener, set `LAB_SERVER_IP` and `LAB_TLS_NAMES` to the new values, then run `python -m security_lab init --renew-certificate` and start again. Certificate renewal does not replace encryption/signing keys. The actual physical two-device smoke test remains pending.

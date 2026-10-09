# External client tools

These optional command-line tools send ordinary requests from the machine where they run. They do not call or import the lab's framework, register attacks, or report outcomes to its detector. Use only an explicit lab target you control.

The client verifies HTTPS certificates by default. Pass the lab CA certificate with `--ca path/to/server.crt` when it is not trusted by the system.

`python attacker_tools/client.py login-attempts --url https://127.0.0.1:8443 --username bob --password-file candidates.txt --limit 5 --ca data/keys/server.crt`

`python attacker_tools/client.py request-record --url https://127.0.0.1:8443 --username bob --password 'demo-password' --record-id RECORD_ID --ca data/keys/server.crt`

`python attacker_tools/client.py probe --host 127.0.0.1 --ports 8443,8444,8001,8002,8003 --timeout 1`

Password files are external input: keep them outside source control and never place real credentials in a repository. Password candidates are tried in file order up to the requested limit; output includes attempt results, never candidate values. Probes connect only to the host and ports supplied on the command line.

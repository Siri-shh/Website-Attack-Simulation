# T17 independent review

Result: **PASS** after D33. No remaining critical or important findings.

Reviewed Dockerfile, Dockerfile.client, compose.yaml and .dockerignore against the T17 brief, dependency lock and package asset manifest. No commands, builds, tests, Git operations or helper agents were run by the reviewer. Implementation files remain unchanged.

## Resolved important finding

**Client exits instead of remaining available** — Dockerfile.client final CMD. time.sleep(float('inf')) raises OverflowError in CPython because infinity cannot be represented as a sleep duration. The independent client container therefore exits immediately. Replace that expression with a loop of finite sleeps, retaining the existing independent-client command and no application/control service. Controller can verify the rejected old expression and statically compile the finite-loop command; actual container liveness remains a T20 check.

## Remaining scope

No additional critical or important findings. Server uses Python 3.13 slim, noninteractive TShark installation, locked project dependencies, complete package assets and the approved serve command. Compose has exactly server/client, internal 172.29.0.0/24 networking with .20/.10 addresses, NET_RAW/NET_ADMIN, persistent data and loopback-published separate HTTPS ports. Healthcheck verifies the server certificate and fetches storage /login without credentials. Client installs the lock-matching requests version and mounts tools/tests/certificate read-only; create_host_path:false prevents accidental certificate-directory creation. Build exclusions protect runtime data, keys, Git, virtual environment and unnecessary reports from the context. No old-project naming, host networking or Docker socket is introduced. T16 SIGTERM cleanup is tracked separately in T16-review.md/D32.

Controller evidence: docker compose config --quiet **exit 0**; resolved service inventory **exactly client and server**. Actual image build, capture operation, client liveness and Docker stop/restart remain T20 acceptance checks. That pre-fix gate is resolved by D33 below.

## D33 final re-review

Dockerfile.client now supplies a JSON-form python -c command with correctly decoded newlines and a while True loop sleeping 3600 seconds per iteration. No other deployment behavior changed. Controller decoded-source compilation **PASS** and repeated Compose config validation **exit 0**. Client command integration approved; actual container liveness remains T20. T16 D32 also passed its independent bounded re-review; real Docker SIGTERM stop/restart remains T20.

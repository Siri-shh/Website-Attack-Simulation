# T18 independent review

Result: **PASS**. No critical or important findings.

Reviewed the T18 frozen brief, attacker_tools/client.py, its README and test_attacker_client.py. Reviewer ran no shell, tests, Git, processes or helpers; no implementation files were edited.

The client imports no framework modules and writes no framework events. Login attempts use an ordinary cookie-preserving Session, fresh login-form CSRF GET for each attempt, credential POST with redirects disabled, input-order attempt limit 1..1000, continuation on 401 and termination on 303/403. Unexpected HTTP responses, missing tokens and request errors return nonzero. TLS uses the supplied CA or system trust and never verify=False. Successful record login precedes the explicit quoted record path; non-success login skips access, and record errors report status without dumping bodies/secrets. Probe targets only supplied host/ports, applies finite positive timeout and closes each socket; login delay rejects negative/nonfinite values. Output omits candidate passwords, cookies, keys and request data. Tests exercise actual client functions through injected requests/socket boundaries.

Controller evidence: attacker-client tests **8 passed in 0.30s**. Real request/capture behavior belongs to T20 acceptance.

## Scoped D34 manifest re-review

Result: **PASS** for the prescribed networking correction. Reviewed current compose.yaml and D34: only internal:true is removed, selecting the ordinary project bridge while retaining the 172.29.0.0/24 subnet, .20/.10 device addresses, eth0 capture, exactly two services, read-only client mounts and host-loopback 8443/8444 publication. This follows the recorded deployment diagnosis; earlier T17 internal-network review is superseded on this point. No extra changes or architecture expansion were requested.

Controller actual evidence supplied: Compose config exit 0; project down without volume deletion followed by up -d exit 0 preserved data; host port mappings now explicitly use 127.0.0.1 for 8443/8444; certificate-verified host storage and console /login both returned 200; the .10 client obtained certificate-verified server /login 200. This approves the observed bridge/publishing correction; further T20 scenarios remain separate.

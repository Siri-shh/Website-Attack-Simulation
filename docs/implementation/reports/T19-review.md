# T19 independent review

Result: **PASS** after the bounded correction waves. No remaining critical or important documentation findings.

Reviewed README.md, docs/DEMO.md and docs/LAN.md against the T19 brief and implemented client/deployment contracts. The approved spec confirms the four goals are confidentiality, integrity, authentication and accountability. Reviewer ran no commands, tests, Git, processes or helpers, and edited no product documentation.

## Resolved corrections

1. README:33–38 invokes the Windows host Python against Docker bridge address 172.29.0.20. Run these Docker examples through docker compose exec client python /tools/client.py and use /certs/server.crt, or explicitly select host-loopback URLs for a host client. Current examples are not executable from the stated location on the target setup.
2. Add the requested local Windows virtual-environment setup, pinned requirements-lock installation and editable project install without re-resolving dependencies. Reuse/link that setup from LAN instead of the current unlocked install.
3. Describe D34 accurately: the normal .29 bridge permits outbound traffic; published ports remain restricted to host loopback.
4. Explicitly preserve the entire new_project directory including .git and durable tracked progress/reports for recovery; preserve runtime data/keys separately when retaining records.
5. Add an optional independent request for Alice seed record ...02 as Bob, demonstrating expected 403/R4 and blocked access rather than disclosure, without introducing a mandatory attack progression.
6. LAN fallback using an existing Docker checkout must first stop Docker serving the shared data, then renew only the certificate after setting the LAN names/IP. Plain init with the existing Docker SAN certificate otherwise refuses the new names. Keep all environment settings in the same PowerShell session.

Remaining scope passes: credentials and routes/flags match implemented contracts; owner ciphertext/hash/signature/timestamps/saved input-size and generation-duration evidence is explained; signature/accountability limits are accurate; rule thresholds and manual blocks are correct; TLS trust/public-cert-only transfer, capture-interface inventory/permission selection, NAT limits, offline isolation/idempotence and explicit key-preserving reset are documented. Physical two-computer verification remains explicitly pending.

Controller evidence supplied: all documented CLI/client help flags checked against implementations and Compose config exit 0. Final review pending one bounded Luna documentation correction wave; no documentation-mirroring tests requested.

## First correction-wave re-review

Docker client targeting, D34 bridge explanation, recovery/.git guidance, optional Alice-record 403/R4 example and pinned LAN setup with prior Docker stop/certificate renewal now pass. README still lacks the requested local Windows venv/locked-install/editable-project/init quickstart; the commands were added only to LAN. Add a short localhost local-setup section or explicit appropriate setup link. Two bounded wording fixes remain: DEMO refers to the foreign request as the second command although it is the third listed command (name the Alice-record request); LAN says two environment values although four are set (say these environment settings). Result remains FIX REQUIRED until this short follow-up. Controller help/flags and Compose checks remain passing; no new implementation scope.

## Final scoped re-review

Result: **PASS**. Verified only the final three corrections: README now provides the local Windows virtual environment, requirements-lock installation, --no-deps editable install, init and serve commands with localhost defaults; DEMO names the Alice-record request without incorrect command numbering; LAN refers to all environment settings in the same session. All six original required corrections and the two wording corrections are resolved. Prior findings/re-review history remain above. Controller CLI/client help flag checks and Compose validation passed; no documentation-mirroring tests or reviewer commands were run. The physical two-computer LAN test remains pending as documented.

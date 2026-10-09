# T03 independent lifecycle review

Reviewer: gpt-6.1-sol, reasoning effort high. Scope: read-only review of identity.py, test_identity.py, conftest.py, related config/database helpers, the T03 brief/report, D18, and approved specification/plan.

Result: **PASS**. No material findings block T04.

## Evidence and reviewed behavior

Controller supplied verification: identity suite **30 passed in 5.22s**. Controller supplied red evidence: 30 intended NotImplementedError failures in 1.36s. The reviewer ran no commands, tests, services, installations or Git operations and changed no product files.

- identity.py:25-30 hides every KeyRing secret from repr; the frozen fields match the agreed contract.
- identity.py:39-46 and 98-134 validate every existing raw secret before publication, require all four 32-byte files, and reload the actual persisted bytes. A malformed file raises a named RuntimeError without replacing any secret. Missing files are checked against both records and any events before creating the keys directory or publishing replacements.
- identity.py:49-63 performs a read-only database inspection and refuses regeneration if inspection fails. It does not narrow protection to signed events; network observations also prevent regeneration.
- identity.py:66-95 publishes fully written/fsynced same-directory temporary files through an atomic non-overwriting hard link; persisted files win if another initializer has already published one. This matches the serialized launcher initialization contract.
- identity.py:137-178 converts configured IP literals to IPAddress SANs and other names to DNSName SANs, compares their exact typed sets, checks a matched RSA-2048 key, SHA-256 self-signature and current validity, and directs SAN mismatch to explicit init --renew-certificate.
- identity.py:181-220 preserves a valid existing TLS identity and its fingerprint. Generated certificates use the lab subject/issuer, RSA-2048, SHA-256, a 365-day validity span and all configured SANs. The keyword-only renew=False interface matches D18.
- Explicit renewal writes only server.key/server.crt. Application AES, signing and both session keys are untouched, including when the configured SAN set changes.
- The 30 tests cover persistent raw identities/public signing key, separate session secrets, hidden repr, malformed lengths, every missing secret over records/signed events/network observations, all-missing protection, certificate properties/fingerprint persistence, SAN mismatch and explicit renewal without application-key changes. The shared keys fixture stays within isolated temporary data.

## Accepted lifecycle limits and integration follow-up

TLS key and certificate publication consists of two atomic file operations, not one atomic pair operation. Interruption can leave an incomplete or unmatched pair; ordinary startup detects this and requires explicit renewal. This is documented in T03 and is acceptable for the agreed serialized initialization lifecycle. T16 must preserve initialization before server threads and wire only the explicit renewal CLI flag to renew=True.

Optional additional regression coverage at the later integration gate: unreadable/corrupt database inspection, mixed missing-plus-malformed secret preflight, and corrupt/incomplete TLS pairs. Source inspection confirms fail-closed paths for these; their absence from the current suite is not a T03 blocker.

## Next action

Controller synchronizes T03 green/review evidence and plan checkboxes, then may dispatch T04. The T03 worker report still says green/review pending and should be updated by the controller to reflect its supplied results and this PASS.

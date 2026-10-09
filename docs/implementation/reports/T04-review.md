# T04 independent cryptographic review

Reviewer: gpt-6.1-sol, high reasoning; independent read-only review.
Result: **PASS**. No material findings; T04 is approved for record/audit consumers.

## Scope and evidence

Read AGENTS.md, RESUME, PROGRESS, the T04 brief/report, approved specification/plan contracts, crypto.py, test_crypto.py, and supporting identity/schema files. Only this review report was written. No shell, Git, tests, package installation, services, or helpers were run by the reviewer. Controller-supplied evidence: deliberate-stub red produced 41 intended failures in 5.27s without collection failure; implementation green produced 41 passes in 5.23s. These outcomes are supplied evidence, not independently executed results.

## Reviewed contracts

- Canonical serialization uses sorted compact JSON, ensure_ascii=False and UTF-8; valid Unicode title/body content is preserved. The encrypted plaintext has only title/body. AES key length is enforced at 32 bytes; each seal generates a fresh 12-byte nonce. AAD binds record_id, owner and version. Ciphertext includes the GCM authentication tag.
- The envelope matches the exact approved schema/algorithm/identity/version/nonce/ciphertext/three-timestamp field set. SHA-256 hashes the canonical envelope bytes; Ed25519 signs those same bytes rather than the displayed hex digest. Seal returns every records-table field with updated/generated timestamp equal to saved_at_us.
- Serialization, nonce generation, AESGCM construction and encoding occur outside the measured operations. Exactly six clock calls surround AES encrypt, SHA-256 calculation/digest and Ed25519 sign, preserving actual deltas. Saved byte counts match UTF-8 plaintext, ciphertext including its tag, and the envelope. The timer test independently instruments operation order and verifies 60/20/50 ns. Opening records performs no generation/signing or measurement updates.
- Opening reconstructs the envelope, validates canonical Base64 and field lengths, compares the digest, verifies the signature, and only then decrypts/authenticates and validates the complete title/body result. Expected stored-format and cryptographic failures become a single generic IntegrityError with suppressed exception chaining. No partial plaintext is returned. Keyed access supports real sqlite3.Row, exercised through an actual in-memory SQLite query in the controller-tested suite.
- Tests include an independent envelope/serialization oracle, cryptographic interoperability, metadata/evidence tampering, malformed stored fields, signed-but-invalid ciphertext/plaintext, missing fields, verification-before-decryption ordering, and preservation of saved observations.

## Existing boundaries

The exact approved envelope authenticates record data and timestamps; durations and byte-count observations are outside that envelope. Consequently a valid cryptographic record does not establish authenticity of those observation fields. This is an existing contract boundary, not a requested envelope change. The primitive does not provide anti-rollback/freshness guarantees beyond the stored version, or protection against a controller of the server signing/encryption keys. It also does not implement authorization, form-length limits, transactions or audit persistence; those are assigned to subsequent service tasks.

No unresolved T04 finding remains. The controller may update durable task completion records and proceed to T05.

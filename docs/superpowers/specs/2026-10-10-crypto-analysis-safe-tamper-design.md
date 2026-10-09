# Administrator cryptography analysis lab

**Status:** Design approved in chat; awaiting user review of this written specification.  
**Date:** 10 October 2026  
**Base commit:** `e5f5d52` (`docs: record M8 checkpoint completion`)

## Purpose and boundaries

Add a professor-facing **Analysis** page to the existing administrator console. It complements the live network dashboard with repeatable local cryptography experiments. Safe tamper is explicitly deferred and is outside this change.

The storage site remains a realistic, always-secure records service. The analysis page does not look up Bob's or Alice's records, read production keys, introduce attack modes, or change storage authorization. It uses only a built-in example or optional administrator-entered UTF-8 text. Inputs/results are transient: no database rows, application audit events, packet capture entries, session values, or URL parameters store them. Analysis responses use `Cache-Control: no-store`. Input is limited to 10,240 UTF-8 bytes, checked by the server.

There are no schema changes, package dependencies, benchmark service, or additional listener. Existing admin authentication and CSRF checks protect the page and all run actions. An unauthenticated or ordinary storage user cannot use the analysis actions.

## Navigation and page structure

The console header links to the existing live dashboard and a separate **Analysis** page at `/analysis`. The analysis page contains three independent panels with separate POST actions:

1. AES-256-GCM encryption/decryption measurements.
2. SHA-256 preimage, second-preimage, and collision analysis.
3. AES-256 confusion, diffusion, and avalanche measurements.

Each panel uses the built-in sample by default and accepts an optional temporary text. A successful POST renders the result in its response; it does not use a session, database, audit event, URL, or client storage to retain the result. User text is HTML-escaped. Do not log submitted text or include it in error details.

The existing dashboard remains a live-monitoring page and continues its two-second refresh behavior. The analysis page does not load its polling script.

## AES-256-GCM encryption and decryption

Use the Python `cryptography` AESGCM API with a fresh, random, in-memory 32-byte key per action. Each operation uses a unique 12-byte nonce. Construct a random 4-byte per-action prefix and append an 8-byte counter to create 1,020 unique nonces for the 20 warm-up pairs and 1,000 timed pairs. No nonce is reused under that temporary key.

Perform 20 warm-up encrypt/decrypt pairs, then 1,000 timed encryptions and 1,000 timed decryptions of the submitted UTF-8 bytes. The 1,000 decryptions authenticate the corresponding ciphertext/tag with its matching nonce and must each recover the exact original bytes. Prepare the key, nonces, and associated data outside timed intervals; time each AESGCM call with `perf_counter_ns()` and do equality checks after timing.

Show the input byte count, sample count, warm-up count, ciphertext-plus-16-byte-tag size, one ciphertext and its nonce, recovered text and equality result, and independent encryption/decryption timing summaries. Report median and nearest-rank p95 (for 1,000 values, the 950th value in ascending order). Identify these as local Python/API operation timings that include call and output-allocation overhead; they are not hardware throughput or a general benchmark.

## SHA-256 and its three security properties

Show the complete SHA-256 digest as 64 hexadecimal characters (256 bits) for the selected input. Do not truncate digests and do not run a toy-digest demonstration. Each property has a separate bounded search of at most 10,000 candidates; compare all 32 digest bytes.

- **Preimage resistance:** Compute the selected input's digest as the target. Search up to 10,000 distinct guesses generated from a panel-specific prefix, an 8-byte counter, and 32 fresh random bytes. Exclude the selected input itself. A match would be another input with the same full digest; no match is expected.
- **Second-preimage resistance:** Keep the selected input fixed as the target. Search up to 10,000 distinct alternatives formed from the input, a fixed separator, and an 8-byte counter. Compare their full SHA-256 digests with the target digest.
- **Collision resistance:** Search up to 10,000 distinct messages generated from a separate prefix, an 8-byte counter, and fresh random bytes. Keep complete 32-byte digests in a request-local dictionary and report a collision only if two distinct messages have identical complete digests.

Each result shows the full target digest, candidate budget, actual attempts, elapsed total search time, and whether a match was found. If a match exists, show its evidence without storing it. Time the whole bounded search, including candidate creation and digest comparison; label it accordingly. A bounded search that finds no match is the expected outcome, not proof that the property holds. State the generic work estimates accurately: approximately 2^256 for preimage and second-preimage search, and 2^128 for generic collision search because of the birthday bound. These estimates concern the full SHA-256 function; they do not claim the lab tested those work factors.

## AES confusion, diffusion, and avalanche

Use the low-level AES-256 block transform only for an isolated one-block experiment. The input block is the first 16 UTF-8 bytes of the selected text, zero-padded when shorter and truncated when longer; display its 32-hex-character value so the tested bytes are explicit. Generate 32 independent random 32-byte AES keys.

For each key, encrypt the baseline block. Then (a) flip each of its 128 plaintext bits separately and encrypt under the same key, and (b) flip each of the 256 key bits separately and encrypt the unchanged block. Compare each 128-bit result with its baseline using XOR/Hamming distance. This performs 4,096 plaintext-bit comparisons, 8,192 key-bit comparisons, and 32 baseline encryptions (12,320 block encryptions total).

Present three clearly bounded observations:

- **Diffusion illustration:** changed output-bit count and percentage for the 4,096 one-plaintext-bit changes, summarized by mean, minimum, and maximum.
- **Confusion/key-sensitivity illustration:** changed output-bit count and percentage for the 8,192 one-key-bit changes, summarized by mean, minimum, and maximum. Explain that this is an empirical key-sensitivity proxy, not a measurement or proof of AES nonlinearity.
- **Avalanche illustration:** for each pair of one plaintext input bit and one ciphertext output bit, count flips across the 32 independent keys. Report the mean absolute deviation of these observed flip frequencies from 50 percent, plus the observed minimum and maximum. Explain the strict avalanche criterion (each output bit changes with probability one-half for each individual input-bit change) and that 32 observations per bit pair are illustrative, not a pass/fail security test.

The raw block transform requires a mode; use a fresh single-block ECB context per encryption solely to expose the AES primitive. ECB is unsuitable for protecting messages. The test uses only random disposable keys, one block at a time, and never encrypts or stores a user message with ECB. State this warning next to the results. Actual records continue to use AES-256-GCM.

## Failure handling and validation

Reject invalid input with a short generic validation message, without echoing arbitrary content in errors. Enforce the 10,240-byte UTF-8 limit on the server. Every action is a CSRF-protected POST under admin authentication. Return no partial or misleading cryptographic result if any benchmark decrypt or internal validation fails. Do not set pass/fail security verdict thresholds on random measurements.

Focused tests must cover: unauthenticated/user denial; CSRF rejection; UTF-8 byte-limit boundaries; complete 256-bit hash comparisons and independent candidate messages; bounded attempt counts and no-match correctness; AES warm-up/sample counts, unique nonces, paired successful decryption, median and nearest-rank p95; exact AES bit-flip comparison counts and 128-bit output width; escaped text; absence of database, production-keyring, and audit mutations. Tests must not require random Hamming distances or timing values to match theoretical averages. Controller runs all commands and the full project suite; GPT-6.1 Sol reviews the milestone before checkpoint.

## Implementation shape and documentation

Keep algorithm functions in one small analysis module that does not import database/audit services or load/use the production keyring. Keep HTTP auth/CSRF/input validation/rendering in the existing console app. Add the Analysis navigation link and page under console templates, with minimal additions to existing console CSS. Add focused unit and route/template tests, and document what each panel means and its limits in the demo guide.

Use the existing model routing from `AGENTS.md`: GPT-6.1 Sol for algorithm/security decisions, debugging, and independent review; GPT-6 Luna for predetermined test-first tasks; the controller runs tests, commands, Docker, and Git. Keep tasks atomic and record exact M9 commit/tag commands in the implementation plan. No product code starts until this spec and its implementation plan have both received user review at their respective gates.

## Documentation references

- [PyCA `AESGCM` documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/): AES-GCM key/nonce requirements and ciphertext/tag behavior.
- [PyCA symmetric encryption documentation](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/): low-level block-cipher context lifecycle and the warning that ECB is insecure for message encryption.

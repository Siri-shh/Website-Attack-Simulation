# Image records, R2 sign-in restriction, and cryptography graphs

Date: 28 October 2026. Status: proposed design, awaiting user approval. This extends the existing storage-security project; the earlier completed milestones remain in force. Safe tamper remains on hold.

## Intent and current baseline

The professor should be able to see encrypted text and images, inspect the evidence that protects each saved version, compare measured cryptographic work as data size changes, and watch an R2 brute-force finding cause a temporary sign-in restriction. The two websites remain separate: ordinary users access only their records; administrators monitor alerts and use the isolated Analysis page.

Already present: AES-256-GCM text records, SHA-256 envelope hashes, Ed25519 signatures, saved generation timings, verified record history, the three bounded SHA-256 property searches, AES bit-flip/SAC measurements, an admin console, deterministic R1–R5 rules, and manual IP blocks. Missing for this request: image records, decryption and signature-verification timings, size-dependent graphs and throughput, a character-change observation, R2 enforcement, and a polished login screen. Completion must be claimed from verified UI and tests, never from a percentage label alone.

## Goals and exclusions

- Show an owner a PNG/JPEG preview and the separate encrypted image evidence, as well as existing text plaintext/ciphertext. Support one image per record, maximum 1 MiB; a record may have no image.
- Preserve encrypted, verified image evidence with every record version. A text edit keeps the image unless the owner explicitly replaces or removes it. Previous versions keep their previous images.
- On an R2 alert, deny storage sign-in for that normalized source-IP/username pair for 90 seconds from the alert timestamp. A correct password does not bypass the restriction. Existing sessions stay active. Restriction attempts do not extend the timer or count as credential failures. Show the remaining wait on the storage login and expiry on the admin console.
- Preserve R1, R3, R4, R5, manual IP blocks, admin sign-in, and the existing R3 120-second window. Consequently, R3 can still trigger during the final 30 seconds of the R2 window after the restriction expires.
- Add clear graphs on record and admin Analysis pages. Show size against measured time and throughput where meaningful, plus graphical SHA property-trial results and AES bit-flip/diffusion/avalanche observations. Include signature generation and verification timings and an explicitly defined character-change observation. Retain numeric tables and honest caveats.
- Make the shared login page visually coherent and distinct for storage versus administration, with usable labels, focus states, error feedback, and countdown. Keep it a real login page without attack-demo controls.

No safe-tamper feature, automatic permanent IP block, new service, third-party charting dependency, filesystem image storage, image editing, or changes to offline pcap analysis are included. Analysis remains admin-only, CSRF-protected, in-memory, and isolated from saved user records and production keys.

## Approaches considered

**Chosen A — versioned encrypted image fields in SQLite.** Add a separate encrypted image BLOB and its evidence to each current record and immutable version snapshot. Extend the canonical signed record envelope to bind image evidence. This makes image ciphertext distinct and keeps ownership/version checks in the existing service. The cost is a careful schema migration and new-envelope compatibility path.

**B — embed image bytes in the existing encrypted text JSON.** This would reuse the old encryption path and need fewer columns, but every text edit/view would carry the whole image and the page could not show image ciphertext separately. It conflicts with the requested separate image evidence.

Immutable external blob references were considered but would add reference lifecycle and cleanup work for no classroom benefit. For R2, deriving expiry from the persisted R2 alert is preferable to a process-local timer, because it survives restart and is visible to the console.

## Record and image behavior

Accept only decoded PNG or JPEG content with matching declared type, bounded dimensions and 1 MiB file size. Do not trust the filename or browser MIME alone. Encrypt raw image bytes with AES-256-GCM, a fresh 12-byte nonce, and authenticated associated data binding owner, record ID, version, image role, and media type. Store ciphertext plus tag in SQLite; never write plaintext images to server storage. Keep the existing text ciphertext separate. Bump the storage upload limit enough for multipart overhead; retain a small admin-analysis input limit.

Introduce an explicit new envelope format for newly saved versions, including versions without an image. The SHA-256 hash and Ed25519 signature cover the canonical envelope containing the text ciphertext metadata and either a null image marker or the image ciphertext hash, nonce, type, and size. Verify this binding and the GCM tag before releasing any plaintext or image bytes. Existing saved versions retain their original envelope verifier; migrations never re-encrypt or rewrite their evidence. Current/latest and history-snapshot comparison includes the new image fields. Image create, replace, retain, and remove occur atomically with the version snapshot and signed audit event. Retaining an image during a text edit still re-encrypts it with a fresh nonce, because the image's authenticated data contains the new version number. Copying a former current version into history preserves its exact original ciphertext, nonce, and version.

Only an authenticated owner can reach image preview or ciphertext endpoints. The record page shows a preview, type/size, nonce, ciphertext hash, shared record signature, generation and read-time measurements, and an expandable full Base64 image ciphertext fetched on demand so ordinary record pages stay small. Historical images are owner-only and version-addressed. Responses carrying decrypted records, images, or evidence use `Cache-Control: no-store`; use a restrictive raster content type and no content sniffing. An integrity failure returns no partial plaintext and follows the existing failure-audit pattern.

## R2 restriction behavior

The fifth verified login failure in 60 seconds already emits R2 for source IP and normalized username. The storage login path checks the newest live R2 for that exact pair and denies sign-in until `R2.time_us + 90 seconds`; admin sign-in and pre-existing storage sessions are unaffected. The check and the credential outcome must be serialized with alert creation so simultaneous requests cannot slip through. A restricted submission produces its own signed, allowlisted audit event, not another `login_failure`, and its response shows a clear countdown without revealing the submitted password. The admin snapshot exposes the expiry/remaining status for active R2 alerts. Manual IP blocks still apply first across the entire storage site. Offline replay alerts do not restrict live sign-in. Once the 90 seconds elapse, a correct sign-in works normally; a new qualifying burst can generate a new R2.

## Measurements and graphs

The storage record page plots each verified version's actual byte sizes against saved AES encryption, SHA-256 hashing, and Ed25519 signing durations. Use text plaintext bytes for text encryption, image plaintext bytes for image encryption, and canonical envelope bytes for hashing/signing, so every horizontal axis names the actual measured input. Include image encryption points when present. Measure text and image decryption plus signature verification during owner reads and label these as **current read observations**, not stored historical measurements. Show elapsed time, data size, and derived effective throughput with units where the input size is defined; a one-version record has one point, with explanatory text rather than an invented trend. Never regenerate saved timings on page refresh.

The isolated admin Analysis page keeps its current 1,000-sample AES-GCM single-input experiment, full 256-bit SHA-256 bounded searches, and AES primitive/SAC experiment. Add a bounded synthetic size sweep (128 B, 1 KiB, 10 KiB, 100 KiB, 1 MiB) with repeated AES-GCM encrypt/decrypt, SHA-256 generation, and ephemeral Ed25519 sign/verify measurements. Display sample count, median and p95 elapsed time, and effective throughput versus input size. Use fresh nonces for every encryption. The user-entered input stays capped at 10,240 UTF-8 bytes; larger sweep buffers are synthetic and never stored or logged. Use a fixed, documented bounded repeat count suitable for an interactive request; retain all raw numeric result values for tests and tables.

Plot the three SHA search attempt counts and elapsed times without claiming that a bounded no-match proves resistance. Plot AES plaintext-bit and key-bit change distributions around a 50% reference and summarize the SAC matrix visually while retaining its full numeric table. For a character-level observation, compare corresponding characters in hexadecimal encodings of two equal-length **single-block AES outputs** after one controlled input change under the same key; show the measured differing-character fraction and method. A 100% character change is not a guaranteed ideal or pass criterion. Label single-block ECB as a primitive measurement only, never storage encryption. Avoid charts that suggest fresh GCM nonces alone prove avalanche behavior.

Render small accessible SVG/HTML charts on existing server-rendered pages with descriptive titles, axes, legends, and adjacent numeric tables. No external chart library or browser-storage state is needed. Use existing page palettes. Make the login page a restrained card layout with service identity and visible form/error states, without stock security imagery or decorative animation.

## Verification and recovery

Test migration against an existing database and a fresh database; verify old text versions unchanged. Cover image type/size rejection, create/edit/replace/remove/history, ownership, content-type/cache headers, tampering of image bytes and metadata, and no partial disclosure. Cover R2 boundary times, pair isolation, signed restricted-attempt events, concurrent fifth/sixth attempts, admin/offline isolation, unchanged R3 behavior, and existing-session behavior. Cover graph labels/data/units, bounded sweep results, nonce uniqueness, transient analysis isolation, signature-verification timings, and a browser pass on both websites. The controller runs all commands and records checks, decisions, reports, milestone commits, and tags under the existing recovery protocol.

Builder choices: exact SQLite column names, chart markup/CSS, fixed repeat count for the size sweep, and layout refinements that do not change the behavior above. Architectural/algorithmic choices go to a reasoning worker; bounded mechanical UI work goes to a Luna worker under `AGENTS.md`.

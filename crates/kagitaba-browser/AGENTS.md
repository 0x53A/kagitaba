# Browser cryptography adapter

This application crate bundles Rust core/CXF cryptography for Firefox through
`wasm-bindgen`. It has no filesystem, transport, device, OS randomness, or secret
logging. `execute` is the native-testable implementation of the exported async
`command(request_json, random_bytes)` function. Both return a JSON string or an
opaque error. The caller supplies fresh `crypto.getRandomValues` bytes per call;
the adapter consumes and clears them, failing on exhaustion. 4096 bytes suffice
for ordinary operations; large recipient lists need a larger buffer (at least
72 + 56 bytes per recipient plus rejection-sampling margin). No random source is
silently substituted.

All binary strings are unpadded base64url. Key/entry IDs are canonical lowercase
hex. `payload` is a JSON **string**, preserving CXF's own parser and unknown-field
checks. Request/response JSON may contain secrets: never log it. Parsed Rust JSON
strings and retained byte buffers are zeroized on drop; returned JS strings,
serialization temporaries, and browser runtime copies cannot be fully erased.

## Command contract

Each request has an `op` plus the fields listed below. Responses are objects:

- `identity_generate`: no fields; returns `identity`, `participantPem`,
  `participantId`, `signingPem`, `signingId`. Identity encodes `KBI1` followed by
  independent 32-byte P-256 agreement and signing scalars. It is secret and must
  never be persisted unencrypted or sent to a page/content script.
- `identity_wrap`: `identity`, 32-byte `prf`, installation string `context`;
  returns `envelope`. Uses HKDF-SHA256 with fixed browser PRF salt and installation
  context, then the core authenticated ciphertext format. `identity_unwrap` takes
  `envelope`, `prf`, `context` and returns the same fields as identity generation.
  Different physical credentials may each wrap the same identity independently.
- `local_encrypt`: `identity`, nonempty `context` (up to 4096 UTF-8 bytes),
  `plaintext` string (up to 16384 UTF-8 bytes); returns `envelope`.
  `local_decrypt` takes `identity`, `context`, `envelope`, returns `plaintext`.
  Used for installation-local remote authentication secrets, not wallet entries.
  HKDF-SHA256 derives a key from the signing scalar with separate browser local
  storage domain strings; core Ciphertext authenticates the complete context and
  uses a fresh injected random nonce. The caller constructs an unambiguous context
  binding the exact canonical HTTPS remote URL and username. Never put decrypted
  tokens in logs, public metadata, exports, or content-script messages.
- `entry_encrypt`: `entryId`, `payload`, `recipients` array of public PEMs;
  returns `primary` and `grants` mapping recipient hex IDs to encoded records.
  Uses CXF Payload::seal, with fresh revision/content key and all recipient grants.
- `payload_edit`: `entryId`, raw `payload` string, `changes` with optional `title`
  and `login` (`username`, `password`, `urls`). Returns a validated raw `payload`.
  Edits the authoritative CXF tree so untouched exact numbers, field labels and
  unknown members survive. JavaScript parsed display objects are not save inputs.
- `entry_decrypt`: `identity`, `primary`, `grant`; returns `payload`. Performs
  record association, grant authentication, decryption, and CXF inner-ID checks.
  The application must verify the committed snapshot before invoking decryption.
- `public_key`: `pem`; returns canonical SPKI SHA256 `id`.
- `hash`: `algorithm` (`sha1` or `sha256`), `data`; returns `digest` and `hex`.
  Git callers include the canonical Git object header in `data` themselves.
- `ssh_sign`: `identity`, `message` containing the unsigned Git commit bytes;
  returns `signature` SSHSIG PEM, using ECDSA P-256, namespace `git`, SHA512 message
  hashing and SHA256 ECDSA, matching the native store. `ssh_verify` takes
  `publicKey` PEM, `message`, `signature`; returns `valid:true` or rejects.
  `ssh_inspect` takes `signature` and returns `publicKey`, `id`; inspection does
  not authenticate or authorize a signer.
- `validate_snapshot`: `files` mapping canonical paths to bytes, optionally
  `previous` with the same mapping; returns `signers` PEM array, `participants`
  mapping ID to PEM and `entries` array of entry IDs. Enforces native layout,
  signer registration, grants, and revision transitions; this is structural
  validation, not history/signature authorization. Limit: 256 MiB decoded files,
  100,000 files, 768 MiB complete request JSON (including both snapshots).
  `participantMetadata` returns validated meta.entry pointers, never decrypted
  names. Legacy name.json/browser.json are parsed only for history compatibility.
  `participants/<p>/index-key` accepts a valid KTW1 wrapper whose recipient is p;
  `cache/<p>/index` accepts up to 2 MiB of disposable cache bytes, requiring p to
  be enrolled with an index key. Corrupt cache ciphertext does not invalidate an
  otherwise signed snapshot; cache consumers rebuild it. Unknown paths still fail.
- `metadata_encrypt`: `entryId`, `participantId`, `name`, `recipients`, optional
  previous decrypted `payload`; creates a new revision of the participant JSON
  defined in root AGENTS.md, preserving unknown fields. An empty name removes
  only the name member. `metadata_decrypt` takes `identity`, `participantId`,
  `primary`, `grant`, and returns secret `payload` and `name`. Both use the shared
  application schema in kagitaba-cxf, separate from credential payloads.
- `passkey_create`: `rpId`, `userHandle` (1–64 bytes), `clientDataJSON` bytes,
  verified `uv` boolean. Returns a fresh ES256 `privateKey` PKCS#8, random
  `credentialId`, `userHandle`, `cosePublicKey`, `publicKey` SPKI,
  `publicKeyAlgorithm:-7`, `authenticatorData`, `attestationObject` (none).
- `passkey_assert`: ES256 PKCS#8 `privateKey`, `rpId`, `clientDataJSON`, verified
  `uv`; returns `authenticatorData`, DER `signature`. `passkey_validate` takes
  `privateKey`, returns `publicKey` SPKI and `publicKeyAlgorithm:-7`; unsupported
  algorithms and malformed keys fail explicitly. The counter is always zero,
  including imported credentials. Flags set UP; absent `kagitabaBackupFlags` defaults to BE=true/BS=false.
  Present eligible/state booleans are preserved; malformed flags and BS without BE
  reject validation/assertion. Applications forward only credential-owned flags. UV is
  only set when the trusted caller supplies a verified decision, not a click.
  The native Android provider can supply `clientDataHash` instead of JSON for
  privileged browser requests: exactly 32 bytes, appended directly to authenticator
  data without a second hash. Only its trusted caller-validation layer may set it.

`passkey_create` optionally takes `prf:true` and `prfEval` with base64url `first`
and optional `second`. It generates an independent 32-byte random `prfKey` and
returns optional `prfResults`; the trusted application persists the key inside
the encrypted credential before returning registration success. `passkey_assert`
optionally takes that `prfKey` and `prfEval`, returning `prfResults`. Both require
verified `uv:true` for PRF. Each output is HMAC-SHA256(prfKey,
SHA256("WebAuthn PRF\0" || decoded input)); each input is limited to 32 KiB.
The key is independent of the passkey signing key and browser wallet-unlock PRF.
No CTAP hmac-secret transport is implemented. Android owns evalByCredential
selection, extension JSON output and encrypted state (`android/AGENTS.md`);
Firefox's provider does not yet expose these optional operations.

The privileged application must bind passkeys to their stored RP ID and validate
actual sender/document/origin, RP relationship, allow/exclude lists, current
authorization, genuine UV, and request lifetime. This crate cannot derive browser
security facts from page-provided JSON. It must not be exposed as a page-callable
generic signing oracle. Persist a new passkey before completing registration.

## Checks and build

`nix-shell --run 'cargo test -p kagitaba-browser'`

`nix-shell --run 'cargo clippy -p kagitaba-browser --all-targets -- -D warnings'`

`nix-shell --run 'cargo build -p kagitaba-browser --release --target wasm32-unknown-unknown'`

The binding generator must match Cargo's exact wasm-bindgen version (0.2.129).
The project shell supplies the WASM linker; install the matching CLI
locally with `cargo install wasm-bindgen-cli --version 0.2.129 --locked --root
target/browser-tools`, then run `target/browser-tools/bin/wasm-bindgen --target web
--out-dir extension/firefox/pkg target/wasm32-unknown-unknown/release/kagitaba_browser.wasm`.
Generated assets are build outputs. Physical PRF, full Firefox integration and
real-site checks remain separate from Rust synthetic unit tests.

`nix-shell --run 'node --test extension/firefox/tests/wasm.integration.mjs'`
executes the actual WASM module after building it and installing extension npm
dependencies. It checks WebAuthn signatures with Node/OpenSSL and transfers a
native signed Git wallet through the browser, adds a browser-signed revision,
reopens it and verifies it again through the native store. All keys are synthetic.


Application helpers: password_generate accepts a serialized password::Rules as
rules and returns password/alphabet, using injected entropy. totp_parse takes uri
and returns credential; totp_code takes credential and integer now (Unix seconds)
and returns code/remaining. qr_scan takes width/height plus base64url grayscale
pixels (at most 2048×2048), returning distinct supported uris for explicit review.
These helpers do not access a wallet or authenticate websites. payload_edit also
supports indexed logins/totps/notes, exact urls and appendCredentials; original
unknown fields and unrelated credentials remain authoritative.

Attachment-aware snapshot validation accepts single KAF1 blobs at
`entries/<entry>/attachments/<blob>` with the native reader’s size bounds. Container
parsing and authentication are deferred until explicit file access; accepting a
snapshot does not authenticate attachment plaintext. IDs are canonical
32-hex, owners exist and are not participant metadata, and each owner has at most
128 blobs. Attachment changes require a new primary revision; recipient reductions
cannot retain old blob IDs. Snapshot totals are 256 MiB; request JSON is bounded to
768 MiB for two base64 snapshots. This is in-memory processing, not streaming.
`validate_attachment_edit` takes `entryId`, new raw `payload` and optional raw
`previousPayload`. Owned descriptors must match exactly, or be absent for a new
entry. This guards client editors that do not implement attachment rekey/removal.

# Firefox client

Daily UI has Wallet and Connection & settings views. Setup leads through physical
key enrollment, public participant request, then URL/username/token connection.
Connection fields survive failures; remote authentication is remembered locally
with encrypted token storage, never in wallet Git history or backup exports.
The wallet provides search, selection/detail, explicit edit/save/cancel, and a
narrow-screen detail dialog. Unsaved edits require confirmation before navigation
and are cleared by locking. Synchronization shows pending/local state, last success,
progress and explicit up-to-date/pulled/pushed/error feedback. Settings expose
remember-token and automatic-sync preferences. New connections default to both;
existing connections can enable them in settings. Automatic sync runs after unlock
and writes, not as a background polling loop. Recovery and public fingerprints
are secondary disclosures, not part of the everyday credential workflow.

Implementation follows ../../FIREFOX-DESIGN.md. All website credential operations
are mediated by the privileged background document. `bridge.mjs` runs in the
hostile page world; `content.mjs` is an isolated routing/fill adapter. Neither
receives private keys. `policy.mjs` validates the real sender and exact HTTPS
origin. Only top-level HTTPS frames are supported. Conditional mediation,
non-ES256 algorithms, enterprise attestation, platform-only selection and
unsupported WebAuthn extensions fall back to Firefox. Regular requests show an
extension-owned floating approval window and always require a fresh physical-key PRF assertion
with user verification before producing a UV=1 software response.

Each installation uses separate P-256 agreement/signing keys. The encrypted KBI1
identity envelope is protected by domain-separated HKDF-SHA256 of a 32-byte PRF
result and core XChaCha20-Poly1305. The explicit unlock RP ID is `kagitaba.local`;
it requires no hosted service. The extension ID is `firefox@kagitaba.local`.
Firefox 150+ permits this RP ID through HTTPS host permission. Enrollment requests
a non-discoverable cross-platform ES256 credential with PIN verification; no
password/ordinary-assertion fallback exists. Actual hardware validation is pending.
Enrollment, unlock and approval explain that Firefox requests a **FIDO PIN**
(bold in the app UI) and physical touch. Firefox owns the actual PIN dialog;
Kagitaba cannot restyle it or detect the precise PIN-versus-touch phase.
Pending WebAuthn requests are aborted on lock and late results are suppressed.
PIV slot policy settings belong to native/Android, not this FIDO participant.

The public participant request contains encryption/signing public keys only.
The PRF parameters and encrypted installation identity remain in local IndexedDB;
they are absent from requests and exports. Reinstallation creates a new participant
which must be enrolled again; the old participant can be revoked. No same-identity
recovery UI or message handler exists. Private identity, PRF results and decrypted
metadata are never persisted. Backup exports include signed Git history only;
legacy recovery bytes in historical commits remain part of that history.
Manual import requires independent root/checkpoint input. Remote connection
takes only URL, username and token/password, trusts the remote on first use,
verifies the genesis signer and full history, and pins its root/head for later checks.

The MV2 persistent background document intentionally targets Firefox. It owns
unlocked state and clears it after five minutes of inactivity, on explicit lock,
or browser shutdown. Pending requests are cancelled on navigation, timeout and
lock. A write already committing may finish durably after lock, but its response
must not deliver secrets. JS/WASM cleanup is best effort, not full memory erasure.
Host permission covers HTTPS websites for password/passkey integration and Git
remotes; HTTP, cross-origin frames and arbitrary filesystem access are excluded.

Diagnostics are shown in the UI and Firefox's extension debugging console (Inspect
from about:debugging). No logfile is written. Only fixed, allowlisted diagnostics
are emitted; library error messages, request arguments, tokens, URLs and server
response bodies must not be logged. Initial connection failures identify fetch,
history verification or connection persistence as the failing stage.

Build from repository root:

```
nix-shell --run 'uv run --no-project tools/build_firefox.py'
```

This creates `target/kagitaba-firefox-unsigned.xpi` and the unpacked `dist/`.
Equivalent individual development steps:

```
nix-shell --run 'cargo build -p kagitaba-browser --target wasm32-unknown-unknown --release'
nix-shell --run 'cargo install --locked --version 0.2.129 --root target/browser-tools wasm-bindgen-cli'
nix-shell --run 'target/browser-tools/bin/wasm-bindgen --target web --out-dir extension/firefox/pkg target/wasm32-unknown-unknown/release/kagitaba_browser.wasm'
nix-shell --run 'cd extension/firefox && npm ci && npm run build && npm test'
```

Use the wasm-bindgen CLI version matching Cargo.lock (the Nix CLI can be older).
Open Firefox `about:debugging#/runtime/this-firefox`, Load Temporary Add-on, select
`extension/firefox/dist/manifest.json`. The toolbar button opens or focuses a
reusable floating wallet window. Approval requests open separate floating windows;
closing one cancels its request. These remain open through external PRF prompts.
Use the shared dark palette, rectangular controls and cyan primary actions.
Entries and settings use focused screens with Back, concise copy and visible Lock.
Editor drafts retain raw JSON and the exact primary revision. Save rejects stale
drafts after synchronization; ordinary form edits use Rust `payload_edit` so
untouched numbers and unknown members survive without JavaScript reserialization.
Temporary add-on data may not survive removing the temporary add-on; export/sync
before doing so. No marketplace signing/publication is part of this build.

First enroll the physical key, export the participant request, enroll it in the
existing native client, and grant access to chosen entries. Follow
`GIT-OPERATIONS.md` for signed transfer and trust bootstrap. Unlock, select an entry,
edit/save locally, then synchronize or export. Toolbar invocation on a website
offers exact-origin password matches and explicit Fill or Save/update. It never
automatically submits a form. A website requesting a passkey opens a separate
approval window; native Firefox remains available through the fallback button.

Imported passkeys remain zero-counter and only ES256 PKCS8 keys can sign. New
passkey registration persists the complete encrypted entry and signed commit
before answering the website. Encrypted saved changes can outlive a cancelled
website request; retain them rather than silently discard credentials.

Tests use synthetic credentials only. Node tests cover RP/origin rejection,
matching, lock epochs, IndexedDB reopen, signed-graph tampering and rollback.
Rust tests cover PRF envelope tamper/wrong key, actual WebAuthn signatures and
attestation, CXF sealing, and SSHSIG. Physical YubiKey, live website compatibility,
and real remote-provider interoperability remain pending unless recorded by an
actual run. No production security audit is claimed.

Git verification accepts the root AGENTS.md conservative merge policy: verify
every commit on both branches, one exact genesis and unique merge base, merge
signer authorized in both parent snapshots, and the exact atomic three-way result
for entries/participants. Both parents count for checkpoints and export traversal.
Conflicting edits/deletions/grants, redundant parents, unrelated roots and multiple
best bases fail. Browser sync remains descendant-only and does not create merges;
use an explicit native merge, then sync. Real WASM interoperability tests cover
native merge transfer, either-parent checkpoints and a browser-signed descendant
reaccepted by the native store.

Connection & settings lists encrypted participant names next to fingerprints
after unlock and can sign name edits/removals. Metadata entries and meta.entry
pointers follow root AGENTS.md; unknown JSON members survive renaming. Names are
excluded from credential lists/password/passkey providers and cleared on lock.
Writes migrate legacy name.json into encrypted entries and prune browser.json.
The verifier accepts clean metadata merges followed by a separate grant-completion
commit, including the narrowly defined additive-grant merge policy in root AGENTS.md.

2026-10-11 encrypted-metadata validation: 21 Node tests and four real WASM tests
pass, including native clean merge plus grant-repair child, either-parent
checkpoints, and decrypting the repaired grant as the newly enrolled participant.
The real Firefox smoke test passes encrypted naming, lock/unlock clearing,
credential-list exclusion, public-keys-only participant export and wallet-only
backup export. Test profiles seed synthetic local installation state directly;
there is no product recovery endpoint. Hardware PRF remains simulated.

Additional integration checks after building:

```
nix-shell --run 'node --test extension/firefox/tests/wasm.integration.mjs'
nix-shell --run 'node extension/firefox/tests/make-fixture.mjs target/browser-test-fixture.json'
nix-shell -p geckodriver --run 'uv run --with selenium --with cryptography extension/firefox/tests/browser_smoke.py'
nix-shell -p geckodriver --run 'uv run --with selenium --with cryptography extension/firefox/tests/transport_smoke.py'
```

The Firefox test installs the extension in a disposable headless browser profile,
uses only a generated synthetic encrypted wallet, and simulates PRF proofs. Its
HTTPS page exercises the actual content/page bridge and independently verifies
the returned WebAuthn signature with Python cryptography. It does not validate a
physical key. The WASM integration test round-trips real native SSHSIG Git history
through the browser implementation and back into the native store.

Validation recorded 2026-10-10: Firefox 155.0.1 with a disposable Selenium profile
passed actual extension installation, synthetic PRF recovery, trust-pinned import,
Rust/WASM decrypt, signed durable editing, exact-origin password fill/capture,
page-bridge software passkey registration/assertion with independently verified
signature, and pending-request cancellation on lock. Ten Node tests, two real
WASM integration tests, full workspace tests (87 plus a doctest), workspace
clippy and portable WASM checks passed. Firefox's PRF requests against a physical
key and interoperability with real HTTPS Git providers remain unvalidated.

The transport regression serves generated signed Git objects through a disposable
local HTTPS `git http-backend`, requires synthetic Basic authentication, and uses
the actual Firefox extension fetch path. It covers fresh-clone remote-refspec
configuration and signed verification after `git-upload-pack`; rejected
authentication must preserve the connection form. No external remote is accessed.

Backend synchronization contract: `sync` returns `outcome` (`up-to-date`, `pulled`,
or `pushed`), `syncedAt` and `head`; accepted replica metadata persists the last
safe outcome/error. Runtime progress events carry only a fixed phase and sanitized
errors. Connection verifies first, then persists its complete accepted head/root,
remote and sync metadata together; optional credential storage or title loading
failures return `connected: true` with a warning rather than falsely reporting a
failed connection. Newly accepted ciphertext can finish persisting after a lock,
but lock suppresses subsequent secret-cache population and private signing.

Remote usernames and preferences are local metadata. Tokens use the Rust
`local_encrypt` envelope keyed from the installation signing identity via a
separate HKDF domain, with exact remote URL and username bound into its AEAD
context. The installation IndexedDB record is never exported or placed in Git.
Remember off removes the envelope and retains a session token only until lock.
Blank token fields preserve a matching saved/session token; changing URL or
username never forwards the old token. Automatic sync is an explicit preference,
queued once after entry writes and unlock; failures remain visible and do not
start a retry loop. Calls serialize with other wallet mutations.

2026-10-11 validation adds real Firefox UI connect/settings/sync feedback,
encrypted token inspection, background restart, locked-token refusal, and actual
HTTPS push/pull between synthetic clients. Node tests also cover single-write
connection acceptance; real WASM tests cover local token envelope scope and
session/persistent transitions. Physical PRF remains simulated in these tests.

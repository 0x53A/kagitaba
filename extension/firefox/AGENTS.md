# Firefox client

The compact header orders brand, browser-wallet/backend name, sync state, refresh,
Tools and lock/close controls. Tools contains the global password generator and
backend switch. Close locks before closing the extension window. Synchronization
feedback lives in the header and live status notice, including while locked.
Enrollment request export has a separate screen from opening a Git wallet;
the existing single replica and PRF-based installation identity are unchanged.
An unconfigured installation opens with a primary native-client action and a
separate enrollment-request action; PRF setup is reached only through enrollment.
Primary controls have distinct hover/pressed states. Keep workflow labels concise.

The snapshot reader accepts `participants/<p>/index-key` (validated KTW1 for p)
and `cache/<p>/index` (at most 2 MiB, requiring the enrolled participant's key).
Signed transfers and ordinary browser writes preserve these bytes. Index keys
remain part of the atomic participant merge unit; cache trees merge independently,
with conflicting cache changes omitted and removed participants' caches pruned.
Firefox currently preserves these caches without using them for its own listing.
Upgrade all replica readers before using native writers that introduce these
paths: the previously signed 0.1.1 standalone add-on rejects them. Its native
gateway does not read wallet Git history and is unaffected. The current signed package
is `../../target/kagitaba-firefox-0.1.2-signed.xpi`; older signed artifacts
are unchanged. Version 0.1.2 includes these reader and UI changes.

2026-10-20 UI/index-reader validation: Node regressions, browser Rust tests, real
WASM native-history interoperability, Firefox wallet/credential smoke,
HTTPS Git transport/settings/sync smoke and native inline-chooser smoke pass.
Screenshots cover wide and narrow wallet headers. PRF/native approvals are
synthetic; no physical key or live website was used. The synthetic installation
fixture waits for a completed background-document reload before sending unlock.

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
inline backend chooser. Browser wallet selection opens the extension-owned
approval window and requires a fresh physical-key PRF assertion
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
automatically submits a form. A website requesting a passkey opens an inline
backend chooser; Browser wallet opens the separate approval window. Firefox
remains available through the fallback button in either UI.

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

## Connected native mode

The wallet window offers **Use native client** before any installation enrollment
and on existing installations. This local mode preference does not create a
participant or copy a wallet. **Use standalone wallet** restores the independent
replica workflow; mode changes lock standalone state and cancel native requests.
Native mode provides **Choose login in native client** and **Cancel request**.
Open/unlock the Linux wallet first, then choose an entry and approve the origin in
its browser request window. Register the host using the native app instructions
in `../../crates/kagitaba-app/AGENTS.md`. Reload/rebuild the extension to include
its `nativeMessaging` permission. No real Firefox profile is modified by builds.

`native.mjs` uses one `runtime.connectNative('kagitaba')` port per fill or WebAuthn request.
Only the privileged background handles native calls; extension-owned app.html
requests trigger fills; validated top-level website requests trigger WebAuthn. The current tab and isolated content script provide the
HTTPS origin and document token. Navigation (including same-origin), tab closure,
wallet-window closure, mode changes, lock, explicit cancel and a 90-second timeout
cancel pending work. After approval, background rechecks origin/document token;
the content script checks them again at fill. Passwords are delivered only to the
selected top-level page and are not persisted or sent to the wallet window.
Native mode forwards validated WebAuthn create/get options to the native client.
The native client selects credentials, verifies a fresh PIV PIN, signs assertions
and persists registrations. Only public response fields are returned to pages.
Unsupported options (including PRF and conditional mediation) fall back to Firefox.
Page cancellation is bound to tab, request ID and document token. Other credential
editing and TOTP remain native-client work.

The native protocol and Unix socket trust boundary are documented with the native
app. Node regression tests cover valid replies followed by host exit, denial,
malformed responses, navigation and cancellation during context lookup or approval.

2026-10-13 gateway validation: native application tests, Node tests and workspace
Clippy pass. `tests/native_smoke.py` passes on Firefox 156 using a disposable
profile/home/runtime directory, the real compiled native host and a synthetic
Unix socket responder. It covers the visible mode switch without enrollment,
password filling, a signed passkey assertion and cancellation propagated to the
socket on navigation. A separate non-JSON frame round trip confirms the compiled
bridge is opaque. The smoke responder is synthetic; Rust tests exercise the
actual native passkey endpoint with encrypted entries and signature verification.
It does not simulate native GUI approval or validate a physical PIV device;
Rust tests separately cover socket serving, scope extraction and the UI lock gate.
Run after building both clients:

```
nix-shell -p geckodriver --run 'uv run --with selenium --with cryptography extension/firefox/tests/native_smoke.py'
```

## Unlisted signing

2026-10-13: version 0.1.0 was signed by Mozilla on the unlisted channel
(AMO version 6571068). Local artifact: `../../target/kagitaba-firefox-0.1.0-signed.xpi`.
Install through Firefox Add-ons → gear menu → Install Add-on From File.
Native host registration remains separate. No public AMO listing was created.

Signing used web-ext 10.5.0 with credentials supplied through WEB_EXT_API_KEY and
WEB_EXT_API_SECRET environment variables, --channel unlisted, --no-config-discovery,
and a matching source archive via --upload-source-code. Do not put credentials
in the repository, command arguments or logs. Future changes need a new version
and another signed submission; the ordinary build remains unsigned.

Source archive and reviewer build instructions are retained under
`../../target/firefox-signing/0.1.0/`. Rebuilding the uploaded source reproduced all
submitted files exactly. The signed package retains identical executable/assets;
manifest JSON was reformatted without semantic changes. Firefox 156 accepted a
permanent installation in a disposable profile with signature enforcement enabled
and confirmed the Mozilla signed state. The user's normal profile was untouched.


## Credential tools

`../../FIELD-AND-GENERATOR-DESIGN.md` defines parity with Linux/Android. The global
generator works before enrollment and in native mode; Generate… applies only to
an entry draft. Shared Rust/WASM owns rules, TOTP parsing/codes and QR decoding.
Ordinary URL edits preserve strings without HTTPS gates or trimming. Multiple
logins, URLs and multiline notes are editable; unchanged values are patched from
original raw JSON rather than reserialized display objects. Password textareas
are hidden until explicitly revealed, retaining embedded newlines losslessly.
Camera scanning requests getUserMedia on user action and stops every track on
completion/cancel/lock. Picture import uses local PNG/JPEG bytes. Review then Add
to draft does not save automatically. No QR URI is fetched. Credential tool
modals expire and copying attempts ownership-aware clipboard cleanup.
Fonts and license are packaged by build.mjs from ../../assets/fonts.
The real-browser smoke includes picture import and a synthetic MediaStream;
physical camera permission/device behavior remains a separate manual check.

2026-10-16 credential-tools validation: Node tests, real WASM tests and Firefox
smoke pass. The smoke includes generator application, unrestricted URL saves,
TOTP PNG import and a real canvas MediaStream through the video scan loop; it also
checks that a permission result arriving after Cancel stops all returned tracks.
No physical camera/PRF was used. Camera acquisitions are epoch-bound so repeated
starts or late results cannot keep an obsolete stream running.

2026-10-20: version 0.1.1 signed by Mozilla for unlisted distribution. Artifact:
`../../target/kagitaba-firefox-0.1.1-signed.xpi` (SHA-256 sidecar alongside).
Matching reviewer sources and verification records are in
`../../target/firefox-signing/0.1.1/`. Source rebuild matches all submitted assets;
Firefox 156 verified the Mozilla signature and accepted permanent installation
in a disposable profile with signature enforcement enabled. Node tests passed.

## Inline passkey backend chooser

Explicit supported website requests now show an inline chooser before opening any
backend. `passkey-chooser.mjs` owns only routing UI in an isolated content script;
this page-hosted surface is not trusted approval UI. It never displays secrets,
account names or repository URLs, and ignores synthetic button clicks. The page
can still obscure or imitate it. Final approval remains in the native app or the
existing extension approval window. `passkey-router.mjs` binds choices to the
validated origin, tab, request ID and document token and rechecks the document.

Native app is offered after Use native client has been selected (existing native
mode installs migrate automatically). `nativeConfigured` retains this choice if
the toolbar returns to the browser wallet; it is not an installed-host probe.
A configured single browser wallet is also available regardless of toolbar mode.
Neither native application startup nor multi-repository storage is implemented.
Unavailable/denied native requests leave the chooser open with a retry message;
Firefox and Cancel remain available even during pending native work. Original
request deadlines remain in force. Lock, navigation, page abort and tab closure
cancel pending work, including preflight initialization. Firefox fallback adopts
the original native promise so asynchronous AbortError is preserved.

The multi-wallet dropdown, multiple native repositories and linked-phone/standard
hybrid QR goals are documented in ../../FIREFOX-DESIGN.md and deferred. Browser
wallet storage, enrollment and management remain unchanged. Builds do not replace
the installed signed add-on; source changes require a future signed version.

2026-10-20 chooser validation: Node tests and both real Firefox smoke tests pass.
Native smoke exercises no dispatch before selection, ignored synthetic clicks,
actual native-host/socket transport, independently verified assertion signatures,
a stopped host with retry, Firefox handoff and cancellation. Browser smoke covers
existing registration/assertion and selecting the browser wallet while the toolbar
is in native mode, plus lock cancellation. Hardware remains simulated and live
GitHub/Zen validation has not been performed. The unsigned chooser build is
`../../target/kagitaba-firefox-chooser-unsigned.xpi`; the existing signed 0.1.1
artifact has not been replaced or submitted again.

2026-10-20: Version 0.1.2 signed by Mozilla on the unlisted channel. Artifact:
`../../target/kagitaba-firefox-0.1.2-signed.xpi` with SHA-256 sidecar. Reviewer
sources rebuild to identical submitted files; signed payload verification and
permanent installation in disposable Firefox 156 with signature enforcement pass.
Signing/rebuild records: `../../target/firefox-signing/0.1.2/`. Normal browser
profiles untouched.

## Immutable owned attachment compatibility

The browser reader accepts `entries/<owner>/attachments/<blob>`: canonical 32-hex
owner/blob IDs, bounded blob size, at most 128 blobs per non-metadata owner.
Like native lazy reads, snapshot acceptance defers container parsing and plaintext
authentication until explicit file access. Attachment changes require a
new owner revision. Removing any existing recipient requires replacing/removing
all old blob IDs. Attachments remain in the owner's atomic merge unit.

Standalone ordinary edits preserve owned manifests exactly and retain ciphertext
blobs; raw JSON cannot add/remove/change owned descriptors. Entry deletion removes
the complete tree. Browser recipient reductions with attachments are rejected;
use the native attachment-aware operation. Imported external file descriptors
remain external and are never fetched. No browser attachment authoring/download
UI is provided yet.

Snapshot readers align at 256 MiB decoded, with KAF1 blob maximum 67,113,992 bytes.
The Rust JSON bridge accepts up to 768 MiB to cover two encoded snapshots, while
Git transfer objects retain a 512 MiB decoded aggregate bound. These are bounds,
not a streaming implementation or memory-availability guarantee; JSON/base64 and
WASM parsing can require several copies. Older signed readers reject attachment
paths and must be upgraded before standalone sync; native gateway mode does not
read Git snapshots.

Text hierarchy keeps screen/section headings prominent, captions/helper/status copy
muted, and actual credential/request values bright. Credential detail blocks have
spaced dividers; tool dialogs and the inline passkey chooser use these roles too.
Scrollable documents, tool dialogs, textareas and the height-bounded inline chooser
use automatic overflow/gutters: no scrollbar space when content fits, with explicit
track/thumb colors for overflowing content.
Native overlay rendering remains controlled by Firefox/platform preferences.

Custom-field editing supports named `string`, `concealed-string`, and `boolean`
values. A label equal to PIN (case-insensitive, ignoring surrounding whitespace)
is concealed by default even when stored as `string`; reveal is explicit and
display policy never rewrites the stored field type. Edits preserve unknown field
metadata and unsupported field types. Boolean values remain CXF `"true"`/`"false"`
strings. Unknown fields remain available in the preserved payload.

Passkey assertions forward credential-owned `kagitabaBackupFlags` to shared Rust
validation/signing. Missing flags retain BE=true/BS=false; explicit flags preserve
imported state. Malformed flags cannot be offered or used. Website request fields
cannot override stored flags. Older signed builds do not support this extension;
local source/unsigned packages do not upgrade installed extensions.

The entry editor groups URLs in one table: each row has a single-line editable
value, Copy and × actions; a full-width dashed + URL row adds another value.
Arbitrary schemes and literal values remain preserved; copying uses the existing
clipboard lifetime policy.

Collection browsing defaults to All entries, followed by Entries not in a collection
and the readable collection hierarchy. Wide windows place navigation left of entry
rows; narrow windows stack a bounded scrolling tree above the list. Selecting a
node shows direct members; nested nodes are independently selectable. Unfiled means
absent from every readable node's local membership. Only unqualified, decoded
16-byte item references matching accessible items resolve. Account-qualified,
external and inaccessible links remain preserved and counted; no link grants
access or triggers credential use. Rows show distinct usernames and a muted
8-character entry ID (full ID on hover), with title/username/full-ID search.
These summaries use the existing unlocked payload cache; lock clears them.

Passkey details show RP, account/display names, copyable credential ID, concealed
user handle with explicit reveal, and recorded backup flags (Not recorded when
absent). Private-key material is omitted from this normal view.

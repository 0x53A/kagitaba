# Android application

Android 14+ Kotlin app (`org.kagitaba.android`) with a Rust JNI adapter at
`crates/kagitaba-android`. This is a credential **provider**, not just a client of
Google Password Manager. Preserve the root crypto/wallet/application boundaries.
Use synthetic wallets only. Never log JNI JSON, payloads, authentication inputs,
HTTP exceptions, intent extras or credential responses. Do not change Git state.

## Design and workflows

The header orders brand, wallet name/sync status, refresh, Tools and a colored
close button. Tools contains the generator, settings and lock; closing returns
to the wallet list and locks the active session. Keep text concise and use the
same separate open/create/enrollment workflows as Linux. Home offers a separate
enrollment-request export using the selected PIV pair, with the native-compatible
public PEM request format; this does not create a wallet or catalog record.
Enrollment uses a transient session, preserves the saved wallet selection, and
restores it when closing or destroying the activity.

Entry editors disable the header Sync action until Save or Cancel returns to
another screen, so successful synchronization cannot discard an unsaved draft.

New-wallet/enrollment PIV discovery offers existing/new-slot radio choices based
on suitable occupied and empty slots. Existing is disabled if fewer than two
P-256 slots exist; new is disabled if fewer than two slots are empty. Labels mark
82/83 defaults. Management key and explicit generation consent appear only for
new slots; wallet creation/export is a separate action after authentication or
generation succeeds. This detects suitable key material, not proof the slots
were originally created by Kagitaba. No extra hardware retry or overwrite occurs.

2026-10-20 workflow parity validation: both JNI ABIs were rebuilt with the shared
store's participant-index reader and cache merge policy, followed by passing JVM
tests, Kotlin compilation, APK assembly and lint. The local artifact is
`../target/android/kagitaba-debug.apk`. Close and lock remain available during
pending work. Physical PIV and Android UI instrumentation were not run for these
layout changes; no user device was modified.

Use the native/Firefox near-black, dark blue and cyan palette, rectangular
48dp controls, clear operation feedback and explicit save/cancel. `WalletTheme`
owns the roles. Keep setup, entries and settings in focused screens with Back;
Lock stays in the header during private work. Remove decorative copy while
retaining trust, hardware consent and destructive-action explanations.
The active backend is the existing
YubiKey PIV participant. `Vault.device` selects `PivIdentity` at the application
layer. `DeviceIdentity` and its Keystore implementation remain intact but are
unreachable from setup/unlock/provider/autofill; no phone participant is generated.
Existing device identity files are preserved, not migrated or deleted.

Private operations use an `UnlockSession` epoch lease outside the lock monitor.
Lock invalidates the lease immediately and suppresses late results. PIV transport
cleanup runs off the UI thread because a pending APDU may await a touch; revoking
the native handle does not await that operation. Login edits change field values
in place, preserving labels and unknown members. Interactive provider association
checks run on the IO dispatcher.

Home starts with the local wallet list and **Add existing** / **Create new**.
`WalletCatalog` stores public local display names and a selected wallet ID;
each wallet has an independent Git directory, root/checkpoint, token and sync
settings under `noBackupFilesDir/wallets/<random-id>/`. Existing single-wallet
installations are registered as `legacy` without moving or deleting their data.
Incomplete drafts are omitted from the list until they have verified wallet state.
Switching wallets locks the old session and invalidates provider tickets. Session
epochs are application-global so a callback from one wallet cannot authorize
another. Activities bind their original Vault; providers use the selected wallet,
not an aggregate of every clone. Home always shows the list on a fresh launch.

**Add existing** names the local wallet, fetches HTTPS Git and verifies/pins its
history before any key/PIN prompt. Read signed participants, signing-key bindings
and device hints while locked. Detect the connected USB/NFC YubiKey, prefer its
recorded serial/slot pair and compare BOTH actual P-256 public keys. For old or
stale hints, scan supported slots 82–95 and match public keys. Detection never
sends a PIN. One match is selected automatically; multiple matching participants
are offered in a picker. Recheck the selected keys before PIN verification. Names
stored inside encrypted metadata cannot be shown before unlock; use fingerprints.
The clone token is saved immediately using installation-owned Android Keystore
protection, independently of the selected YubiKey. No new Android participant.

**Create new** either uses an existing P-256 pair or generates two keys in empty
PIV slots. Public discovery lists only suitable occupied/empty slots. Generation
requires explicit checkbox consent, the existing PIV PIN and management key;
a factory-management-key button is an explicit convenience, never an automatic
attempt. Both slots and device serial are checked before authentication/mutation;
each generation also checks emptiness. No overwrites, resets, PIN changes or
automatic retries. New-slot policy pickers default to PIN Once for both keys,
encryption touch Cached and signing touch Always, matching native provisioning.
Each offers PIN Once/Never and touch Never/Always/Cached; changes clear consent.
PIN Always needs per-operation PIN prompts and is not offered. The PIV PIN label
is bold; Kagitaba still verifies a PIN on unlock with hardware PIN Never.
Existing device-reported policies are read-only in the slot/participant chooser
and Settings. Unknown bytes are displayed without rejecting the public key.
Existing PIN Always is explicitly marked unsupported for repeated operations.
Policies are fixed at key creation; the UI never silently replaces keys.
Partial generation failures cannot be rolled back and tell
the user to inspect the device before retrying. Once generated, a separate create
button signs the new wallet with that pair; retrying signing does not generate
more keys. The genesis stores its serial and slots for future auto-detection.
Requires YubiKey 5.3+ metadata/P-256 support, as on Linux. Uninstalling the app does
not lose the hardware identity; reconnect and establish local trust anew.

YubiKit Android/core 2.9.0 provides USB/NFC discovery and raw smart-card transport
(compatible with our SDK35 build). It does not implement wallet cryptography.
JNI holds a process-local handle to the shared Rust `kagitaba-device::Session`;
its private operations call the Android transport via a GlobalRef. Core ECDH
unwrap, payload encryption and wallet signing all remain Rust. Native desktop USB
is an optional default-on `kagitaba-device/usb` feature, disabled for Android.
Provider requests require fresh PIV PIN entry. Background provider enumeration
returns an authentication action and never triggers hidden hardware touches.
Provider/autofill saves perform optional synchronization in the foreground before
closing the activity. Git token access uses device storage, not a PIV touch.
All SecureActivity screens show pending private-command guidance through the
Rust session observer and JNI PivConnection callback (kept for name-based lookup).
The banner distinguishes Always/Cached/Never; it cannot observe an actual card
touch-wait signal. Completion, failure and lock clear it, and callbacks from old
connections are ignored. Provisioning also gives conditional touch guidance for
management authentication. Keep the key connected/in NFC range for private
operations; configured touch policies apply. Leaving an activity stops NFC reader mode, so subsequent provider
steps may require another tap/unlock. USB removal locks the wallet. NFC loss is
detected by the next operation; no cached PIN is used to reconnect silently.

Wallet screens show accessible items, support search, reveal/hide and edit
passwords, generate random passwords, copy with Android's sensitive-clipboard flag,
show passkey metadata, and delete entries. Clipboard cleanup after 30 seconds is
best effort when Android permits access, and never clears another app's replacement.
Edits preserve unknown CXF fields. Existing recipient sets are retained; new
entries grant registered participants access. Collections and unsupported CXF
credentials are preserved in Git but are not an Android collection editor.

The connection screen retains values on failure. Git tokens use AES-256-GCM with
an installation-owned, non-exportable Android Keystore key, without a per-operation
hardware-key or biometric prompt. Envelopes live in private no-backup wallet state;
AAD binds the wallet ID, exact URL and username. They are never part of wallet Git
history or transfers. DeviceToken clears temporary byte buffers; caller/JGit Strings
retain the existing best-effort memory hygiene limitation. Saving works while the
wallet is locked. Blank token on an unchanged connection retains the existing
device token; endpoint/account changes do not reuse it. Old participant-wrapped
and software-identity tokens require explicit re-entry; no automatic migration.
Successful connection saving removes the old envelope atomically. Missing or
unreadable device credentials produce a fixed Connection settings error. Unlock
sync feedback does not claim an entry was saved. Synchronization is explicit or
triggered after unlock/save, not background polling while locked. HTTPS only,
no redirect following, no embedded URL credentials. Branch is `wallet`. JGit
fetches into a remote ref; Rust Store verifies committed bytes, signer authority,
signed history, and checkpoints before accepting a descendant. The shared Rust
store accepts conservative two-parent merges using root AGENTS.md's policy,
including checkpoints on either parent. Android sync does not create merges:
divergence is rejected without discarding local commits; merge explicitly in the
native app, then synchronize Android. Push is never forced. First connection
bootstraps trust from the HTTPS repository's verified genesis and pins it locally,
the same first-use model as Firefox. Changing URL retains pinned trust.

Connection & settings → Participant names decrypts optional metadata entries
after unlock and shows names with fingerprints. Renames are encrypted revisions
granted to all participants, referenced through meta.entry. Unknown JSON fields
survive edits; clearing a name keeps other metadata. Names are excluded from
credential/provider lists and are never used for identity or access decisions.
Connect uses public fingerprints and YubiKey serials, never decrypted names.
See root AGENTS.md for the schema and two-commit metadata merge policy.

JNI store errors retain fixed categories for unsupported history, checkpoint
divergence/rollback, ambiguous bases, merge conflicts, invalid/unauthorized
signatures, malformed records, storage I/O, dirty/locked working copies and stale
writes. SecureActivity allowlists exact messages and never forwards raw Git,
HTTP or parsing error text. Automatic-sync failure feedback survives navigation
back to the wallet screen. Older clients' generic "Wallet validation or storage
failed" can indicate a now-supported merge; do not reset trust to bypass it.

An encrypted Git transfer can export backups or import signed updates to an
already connected wallet. Imports cannot replace trust or roll back a checkpoint.
Storage uses app-private `noBackupFilesDir`; Android backup is disabled. Lock on
screen-off and after two minutes of inactivity. No background query refreshes the
idle timer. Activity windows use FLAG_SECURE, secret inputs disable saved state,
and lock cancels UI jobs and drops the session identity. JVM JSON/String copies
are not reliably erasable; Rust owners and bridge byte arrays are cleared where
possible. This is best-effort memory hygiene, not protection from a compromised OS.

## Provider APIs and authorization

- `androidx.credentials.provider.CredentialProviderService`: create/get password
  and public-key credentials. Android binds with BIND_CREDENTIAL_PROVIDER_SERVICE.
- Begin/query responses carry CreateEntry, PasswordCredentialEntry,
  PublicKeyCredentialEntry or an AuthenticationAction while locked.
- Private activities receive one-shot, explicit mutable PendingIntents, required
  so Android can attach the provider request. A random URI binds each selection
  to an expiring in-memory ticket; intents contain no private keys or passwords.
  Recheck actual provider request, caller, RP, account and allow/exclude lists at
  selection. Process death expires tickets; restart the request from its app.
- `PendingIntentHandler` extracts platform-supplied requests and sets typed
  Create/Get responses. Persist a signed new passkey entry before returning
  registration success. Never return success after storage failure.
- `android.service.autofill.AutofillService`: authenticated filling and explicit
  password saving for existing login forms. Parse bounded AssistStructure trees;
  mixed web domains, insecure web origins and untrusted browser certificates fail
  closed. Native app links require explicit user approval and bind signing certs.
- Browser delegation uses CallingAppInfo.getOrigin with a bundled, release-only
  snapshot of Google's privileged browser signing allowlist. Native app passkey
  requests require HTTPS Digital Asset Links granting common.get_login_creds to
  the exact package and current signing certificate(s). No permissive name-only
  checks. Do not impose suffix-origin checks on an authenticated privileged
  browser's RP: it owns WebAuthn Related Origin Requests validation.
- Password lookup uses exact HTTPS origin or encrypted, explicitly approved
  native package/certificate association in the `kagitabaAndroid` entity extension.
  A CXF androidApps bundleId alone does not authorize release.

Passkeys use the existing Rust ES256 implementation and standard CXF PKCS#8
storage: imported compatible passkeys are usable, and newly created passkeys can
sync to native/Firefox. UP and actual UV are set after fresh device authentication;
the counter stays zero. New/legacy credentials default to BE=true, BS=false;
imported `kagitabaBackupFlags` preserve explicit eligible/state booleans. Malformed
flags or BS=true with BE=false reject usage. Website options cannot override these
credential-owned flags. Android privileged
browsers may supply a 32-byte clientDataHash: sign it directly, never hash it
again or substitute fabricated client JSON. Native apps receive provider-generated
clientDataJSON with their certificate-hash origin. Attestation is `none`.
ES256, credProps, WebAuthn PRF and largeBlob are implemented. PRF uses an
independent random 32-byte per-credential key and Rust HMAC-SHA256 over
SHA256("WebAuthn PRF\0" || input), after fresh device UV. Registration supports
enablement and first/second evaluation; assertions support eval and
evalByCredential (validated against allowCredentials). PRF input values and blobs
are limited to 32 KiB each within the existing 64 KiB request limit.
The encrypted CXF passkey object preserves `kagitabaPasskey` with `version: 1`,
optional base64url `prfKey` and optional base64url `largeBlob`. This is an
application extension, not a standard CXF PRF export field. Keep this state with
the credential for its lifetime. Existing/imported passkeys without this state
return no PRF results; never invent a replacement PRF secret on assertion.
Other clients preserve this opaque state but do not yet expose these extensions.
largeBlob supports preferred/required registration, reads and signed writes;
writes require exactly one allowed credential and reject simultaneous read/write.
Missing data and a stored empty blob are distinct. Writes preserve unknown fields
and grants, check the selected plaintext still matches under the wallet operation
lock, and return written:true only after durable signing, then optionally sync.
Unsupported extensions (including raw CTAP hmac-secret and credential-protection
policies) still fail explicitly. Typed extension errors show at most eight bounded
ASCII identifiers, never option values or arbitrary exception text; malformed
identifiers are replaced. Preflight reports errors before the Save/Sign in button.
No hybrid/QR authenticator transport,
credential transfer protocol, SSH remote authentication,
background conflict resolution is claimed.

OS provider settings and Autofill settings are accessible in the app. Enable
Kagitaba as the preferred password/passkey/autofill service before testing.
Actual support also depends on the calling app/browser using these Android APIs.

## Build and verification

`nix-shell android/shell.nix --run 'uv run --no-project tools/build_android.py'`

Builds arm64-v8a (physical phones including Pixel) and x86_64 (emulator), runs JVM
tests and lint, and produces `target/android/kagitaba-debug.apk`. This APK uses a
local Android debug signing key; it is not a published or attested release. JNI
libraries must be rebuilt after Rust changes. For just one ABI pass
`--abi arm64-v8a` or `--abi x86_64` to the build script. All native libraries use
16 KiB ELF page alignment. The Nix shell supplies SDK 35, NDK 27, JDK 17 and Gradle.
The script builds Android std from matching Nix Rust sources using invocation-local
RUSTC_BOOTSTRAP/build-std, without modifying global Rust toolchains or SDKs.

Rust: `nix-shell --run 'cargo test -p kagitaba-android -p kagitaba-browser'` and
`cargo clippy -p kagitaba-android -p kagitaba-browser --all-targets -- -D warnings`.
Android: `nix-shell android/shell.nix --run 'gradle -p android :app:testDebugUnitTest :app:lintDebug'`.
Emulator tooling: `nix-shell android/shell.nix --arg withEmulator true`.
Keep emulator data under ignored `target/android`; never reset a user's phone.
On a disposable API-35 emulator with PIN `123456`, install the separate synthetic
login fixture and run instrumentation with:

```
ANDROID_SERIAL=emulator-5580 gradle -p android :autofill-probe:installDebug :app:connectedDebugAndroidTest
```

Tests refuse the PIN/UI flows on physical hardware. The earlier device-PIN UI
tests target the retained, disabled software backend and must be reworked before
running the whole instrumentation suite in PIV mode. Run `PivInteropTest` and
`NativeInteropTest` by explicit instrumentation class selection for this mode.
`PivInteropTest` uses a synthetic APDU card with independent Android JCA ECDH and
ECDSA; it never connects to a real key. NativeInteropTest checks the
packaged JNI library against Android JCA and JGit. ProviderFlowTest supplies
synthetic framework requests through one-shot pending intents, exercises the real
PIN/approval activities, and decodes their typed password/passkey responses. It
uses an installed, allowlisted Chrome certificate as the simulated browser caller;
it is not a live website interoperability test. AutofillFlowTest uses the actual
Android Autofill service and a separate native login app, including the system
save prompt and certificate-bound matching. The `autofill-probe` APK is test-only
and is not included in the Kagitaba APK. ProviderProbeActivity is a private,
debug-only result collector absent from release builds.

`tools/android_ui_smoke.py` additionally checks initial PIN enrollment, wallet
creation, editing and lock/unlock on a fresh installation in that emulator.
Physical PIV USB/NFC, provider dialogs and real-site interoperability
remain separate from Rust/JVM tests. Record actual emulator/device results, never
infer them from successful compilation. Never enter a test PIN on physical hardware.

Passkey-extension validation: targeted Android/browser Rust tests (including
independent Python HMAC PRF vectors and encrypted CXF state round trips), 14 JVM
tests, Android lint, Clippy, browser WASM checks and both native APK ABIs pass.
JVM coverage includes PRF input selection, blob persistence failure/round trips,
unknown-field preservation, bounds, value-free errors and malformed allow lists.
The ChatGPT Android app's exact requested extensions and live registration result
remain unverified; the previous generic rejection did not identify the extension.

Validated in this implementation: 91 workspace Rust tests/doctests, workspace
Clippy, portable WASM checks, five JVM policy tests, Android lint, and API-35 x86_64
emulator runs of the two JNI/JGit/JCA tests, the real-PIN provider activity test
(passkey create/get and password create/get), and the actual platform Autofill
save/fill test. Initial PIN enrollment and wallet edit/lock/unlock also passed
`android_ui_smoke.py`. The provider activity test uses synthetic system requests;
the platform account-picker integration and live websites still need device
validation. These earlier UI results concern the now-disabled software backend.

PIV/multi-wallet validation: 15 targeted Rust tests, Clippy, six JVM tests, lint,
both Android ABIs, and eight API-35 emulator integration tests passed. These are
four PivInteropTest cases, two NativeInteropTest cases and two WalletWorkflowTest
cases. They cover synthetic APDU PIN verification without retries, JCA-backed
ECDH/signing through JNI, signed persistence, payload/token decryption,
wrong-context rejection, session invalidation, PIN-free non-default-slot matching,
consented provisioning with occupied-slot refusal, clone verification before
unlock, independent wallet trust and the home → Add existing UI sequence.
No physical key was provisioned by automated testing. Physical USB/NFC
interoperability still needs user-driven validation.

## API references consulted

Android provider guide: https://developer.android.com/identity/sign-in/credential-provider
Autofill: https://developer.android.com/identity/autofill/autofill-services
Privileged callers: https://developer.android.com/identity/sign-in/privileged-apps
Bundled browser certificate data: https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
KeePassDX reference (API patterns only; no implementation code copied):
https://github.com/Kunzisoft/KeePassDX/tree/master/app/src/main/java/com/kunzisoft/keepass/credentialprovider


## Credential tools

`../FIELD-AND-GENERATOR-DESIGN.md` defines shared generator/TOTP and field behavior.
Header Generate works while locked; entry Generate… sets only the draft. JNI
calls shared Rust password and OTP code. URLs remain exact strings on save;
multiple logins/URLs, multiline notes and TOTP fields can be edited independently.
All fields/revealed credential text use bundled DejaVu Sans Mono.
TOTP imports support camera, pictures and pasted otpauth URIs, with a review/Add
to draft step before Save. Camera2/TextureView and ImageReader keep camera data
inside the app. CAMERA permission is requested only on Scan camera. QrPixels
converts bounded bitmaps or strided YUV planes for the shared JNI decoder.
Camera sessions close on backgrounding/lock/dismissal. Picture-picker callbacks
are tied to their live dialog and epoch. No gallery or temporary image is written.
CredentialToolsTest uses a synthetic fixture with the packaged JNI library;
physical-camera testing is not implied by compilation or synthetic tests.

2026-10-16 credential-tools validation: both Android ABI builds, JVM tests and
lint pass. CredentialToolsTest passes on an isolated API-35 emulator: packaged
JNI generator parity, multiline values/URL retention, PNG and padded YUV-plane
QR decoding, global generator UI and Camera2 preview start/stop. This exercises
an emulated camera, not a physical key or camera. Picture decode requests mutable
bitmaps so best-effort erase/recycle cleanup cannot turn success into an exception.

Text hierarchy uses sans-serif screen/section headings, muted 13–14sp field labels
and support/status copy, and brighter monospace credential values. Credential
sections use spacing and thin dividers; list subtitles are smaller and muted.
Shared generator, TOTP, PIV and provider/autofill surfaces use the same roles.
ScrollViews and multiline editors enable vertical scrollbars with fading disabled
and inset space. The shared helper sets an explicit thumb drawable before
disabling fading: programmatically enabled EditText scrollbars can otherwise
crash in framework onDrawScrollBars with a null ScrollBarDrawable. A synthetic
multiline drawing test passes on the Pixel for fitting/overflowing/fitting text,
without accessing a wallet or hardware key. The platform range/extent gate hides the thumb and default track
when content fits; fading is disabled only for a scrollable range. Platform
spinner/popup behavior remains Android-owned.

Custom-field editing supports named `string`, `concealed-string`, and `boolean`
values. A label equal to PIN (case-insensitive, ignoring surrounding whitespace)
is concealed by default even when stored as `string`; reveal is explicit and
display policy never rewrites the stored field type. Edits preserve unknown field
metadata and unsupported field types. Boolean values remain CXF `"true"`/`"false"`
strings. Unknown fields remain available in the preserved payload.

The entry editor groups URLs in one table: each row has a single-line editable
value, Copy and × actions; a full-width dashed + URL row adds another value.
Arbitrary schemes and literal values remain preserved; copying uses the existing
clipboard lifetime policy.

The entry list defaults to All entries. A compact collection picker offers Entries
not in a collection followed by indented readable collection nodes. Selection shows
direct members; unfiled excludes local membership in every readable nested node.
Only unqualified decoded16-byte references to accessible items resolve. External,
account-qualified and unavailable links are counted and preserved, never used to
grant access or open secrets. Rows show usernames and muted8-character entry IDs;
the full ID remains in accessibility text and searchable. Browsing uses already
unlocked payloads; no background collection decryption or new provider scope.

Passkey details show RP, account/display names, copyable credential ID, concealed
user handle with explicit reveal, and recorded backup flags (Not recorded when
absent). Private-key material is omitted from this normal view.

## Participant-index listing

Android ordinary wallet listing uses the shared KTI3 encrypted participant index.
The JNI `store_catalog` operation verifies signed history against the saved trust
checkpoint, unwraps only this participant's index key and reuses current rows.
Missing/corrupt/older indexes rebuild through shared extraction; changed primary
or own-grant digests refresh only their affected rows, and deleted/inaccessible
entries disappear. Missing keys are provisioned once. Changed cache/wrapper bytes
are saved through normal participant signing; unchanged caches do not sign or
commit. First rebuild/writeback can therefore require hardware touch. A signing
failure publishes neither replacement cache nor a new accepted head.

If valid payload summaries exceed the index encoding limits, catalogue loading
returns complete transient summaries (including collection membership) without
writing a cache, key wrapper or commit. Existing wrappers and caches are retained.
The shared extraction path still validates/decrypts payloads and filters grants;
trust, key-operation and signing errors remain errors, not fallback triggers.

The Kotlin list carries summary fields and collection hints, never placeholder
credential payloads. Selecting a row shows indexed title, accounts, scopes and
credential-presence flags; explicit **Show more** verifies and decrypts only that
entry. Index hints never authorize credential use. Chosen provider tickets also
open their exact entry directly. Foreground provider candidate matching retains
its full-payload matching path; background provider discovery still never calls
private hardware operations. Index-backed provider candidate filtering is not
claimed by this change.

Catalogue calls use the existing serialized operation mutex and unlock lease.
Lock discards UI work and rejects late results; checkpoint persistence checks the
captured unlock epoch under the state gate. A signed cache-only update completed
while lock invalidates the lease may remain a verified descendant of the previous
checkpoint; the next open verifies it normally. There is no persistent plaintext
index and no global decrypted Rust index cache. Android/JNI strings follow the
existing best-effort memory hygiene limits.

Entry summaries and decrypted details show Collections with one root-to-node
path per direct membership, derived from readable collection index hints. Ancestor
names provide the path, not implied parent membership. Multiple roots and nested
memberships are retained; inaccessible collections are not inferred. This display
requires no additional key operation and does not authorize access.

# Native application

Run from the workspace: `nix-shell --run 'cargo run -p kagitaba-app'`.
This is the Linux prototype; PWA is not implemented. Android is documented in
`../../android/AGENTS.md`. The separate
standalone Firefox client is documented in `../../extension/firefox/AGENTS.md`.
Preserve the existing password-manager backup while testing. Importing a passkey
into this native application is storage, not registration as an OS authenticator.

## Design pattern

Rectangular controls, near-black background, dark blue surfaces, pale text and
cyan primary actions. Proportional 16px interface text, muted 13px field labels and
secondary instructions, 18px subsection titles and 25px page headings. Credential
values and fingerprints use explicit monospace; warnings retain distinct color.
Scrollable areas show solid, nonfading scrollbars when content overflows; areas
that fit show no scrollbar. Native system pickers follow desktop settings. Hairline separation and
no rounded corners or shadows. `theme.rs` owns the visual language.
URL editing uses one URLs table: single-line inputs with Copy and remove on the
right, followed by a full-width dashed + URL control. No repeated row labels.
Android and Firefox share these roles and task-focused navigation. Keep copy
concise, retaining instructions needed for trust, access and destructive actions.

The welcome screen contains Open wallet, Create wallet and Create enrollment bundle, then the opt-in Remember opened
wallets checkbox, then favorites above recent wallets. Saved locations use contiguous split buttons with colored star and remove actions. Stars toggle favorites;
the X removes only a saved location, never wallet files or trust records.
Disabling history immediately clears recents, including persisted recents.
Explicit favorites survive history opt-out. Only successfully verified/opened
wallets enter history; recents are deduplicated, newest first, capped at 20.
Navigation preferences live in `$XDG_DATA_HOME/kagitaba/navigation.json` (0600,
atomic replacement), with the usual `~/.local/share` fallback. They contain only
paths/preferences, never credentials, titles, PINs or trust decisions. Linux path
bytes are hex encoded to preserve non-UTF8 paths; this is not encryption.

Opening chooses a folder, verifies trust/history, then offers detected or manual
participant/device/slot selection. Unlock explicitly loads the search index. Unlock and new-key enrollment are separate flows.
Create opens the form directly, with an editable location and folder chooser,
then prepares a key and explicitly creates/signs. The header orders brand, wallet
name, fetch state and refresh, with tools and a colored close button at the right.
The wallet's favorite toggle is a star icon in that right-hand header group.
The PIV PIN field includes its arrow action inside the right edge; Enter in the
focused field submits the same action. Empty/disabled input and absent devices
cannot submit, and successful preparation disables further PIN submission.
The wallet workspace has an entry list on the left and details on the right;
below 780pt available width, details use a scrollable modal with Close and Lock.
Import (source, preview/recipients, completion), Keys & access, and Backups & updates
are separate screens with Back. Lock remains available during work and in the
details modal. Closing a wallet waits for the worker to drop its store and session.
Unsaved entry edits prompt before navigation; locking always clears immediately.
Entry lists sort loaded titles alphabetically (case-insensitive), then encrypted
entries by ID. Search matches indexed titles, account names, URLs/scopes or entry IDs, trims surrounding spaces,
and offers Clear / Escape while focused plus result counts and no-match feedback.
The list caches normalized search text, sorted order and filtered results until
its data/query changes, and only renders visible rows. Lock drops these caches.
Selecting an entry shows only its current participant-index summary: title,
usernames, scopes and password/TOTP/passkey presence. Show more explicitly decrypts
and opens the editable payload. Selection itself sends no private operation.
Index summaries are bound to the verified snapshot and unlocked participant;
snapshot replacement and lock clear them. Android scopes display application IDs
and available names/certificate fingerprints; scope text is selectable without
opening links. Presence flags remain hints, not activation or authorization.
Selecting the current entry preserves its draft without another hardware request.
Editors put Save / Discard and saved/unsaved state above the fields; unchanged
entries cannot be saved redundantly.
Discard edits asks for confirmation, restores the loaded payload and recipients
without decryption, and clears widget undo/reveal state. Discarding a new draft
closes it. Deletion of saved entries is grouped in an expandable section and
retains explicit confirmation; it opens by default for inaccessible entries.

New entries initially select only the current enrolled participant. Enrollment
does not imply entry access. Raw CXF editing remains an explicit advanced option.

Password/note values are masked with per-field Show/Hide controls. Copy buttons
expire their clipboard contents after 30 seconds only if
the contents still match. Manual selection/copy in the advanced editor and system
clipboard history are outside that guarantee. Complete CXF JSON is an explicit reveal/edit panel for unsupported
fields, provenance and collection links. No external resource URLs are fetched.
File dialogs default to the native system portal through the `native-dialog` Cargo
feature. Build with `--no-default-features` to use floating in-window egui-file-dialog
choosers. Native dialogs run off the UI thread; locking discards late selections.

## Hardware workflow

Requires a YubiKey with PIV and metadata support (5.3+). FIDO-only Security Keys
cannot implement this PIV backend. USB CCID is accessed directly using Rust nusb;
no ykman, libusb, PC/SC or OpenSSL is linked or spawned by the application.
OS windowing, graphics, clipboard and USB interfaces remain platform boundaries.
Other programs holding the CCID interface must release it. USB permissions are
provided by the OS; the app never changes system rules or detaches another owner.

Creation and enrollment first verify the PIN once, then inspect all retired slots.
Use existing slots is enabled when at least two usable P-256 slots are detected;
this detects compatible keys, not Kagitaba provenance. Otherwise new-slot enrollment
is selected. The authenticated device connection remains in the worker, without
retaining the PIN, until an explicit create/use action or lock/close/refresh.
Slot selection does not generate keys. Create keys requires management authentication
and explicit consent for the selected slots; Create wallet becomes available after
success. The enrollment workflow exports public participant JSON independently
of creating or opening a wallet.

Setup explicitly generates P-256 keys in two selectable, distinct retired PIV
key-management slots from 0x82–0x95, defaulting to 0x82 (ECDH) and 0x83 (ECDSA
signing). Select the same pair for setup and subsequent unlocks. New wallets record
the raw device serial and selected slots in signed `participants/<id>/device.json`.
Existing wallets can record an enrolled, unlocked device with "Remember device in
wallet" (a signed commit). This optional version-1 JSON contains `serial`,
`encryptionSlot` and `signingSlot` (numeric byte values). Older wallets without it
still open. Serial numbers are public routing metadata, never identity or trust.
Opening a verified wallet scans USB and selects a unique serial/slot match; refresh
also applies metadata. Multiple matches require manual selection. Selecting a
device applies its pair only if that device has a unique mapping. Unlock checks
both public keys against any matching recorded participant. No automatic PIN
submission or key generation occurs. Discovery reads the serial with the PIV
GET SERIAL command (no PIN), because USB descriptors commonly omit it. Inaccessible
devices remain listed with their serial unavailable. Refresh is disabled while
unlocked to avoid interfering with the active CCID session. Metadata travels in
backups/pulls and is removed on participant
revocation; historical snapshots retain it. An unlocked session pins
its selected slots for every private operation. Changing slots or the selected
device clears provisioning consent. It checks BOTH slots first, refuses occupied or
unreadable slots, and never resets the device. No certificates are written;
public keys are read through PIV metadata. Existing PIN and management-key values
are supplied by the user; global PIN/management key are not changed automatically.
The factory-management-key button is explicit, not an automatic fallback.
Management authentication supports TDES and AES-128/192/256 according to metadata.
New-slot setup defaults to PIN-once/touch-cached for encryption and
PIN-once/touch-always for signing. Each slot offers PIN Once or Never and touch
Never, Always or Cached. PIN Always is not offered: sessions discard the PIN and
do not implement per-operation PIN prompts. Kagitaba still verifies the PIV PIN
at unlock with a hardware PIN Never policy. Changing slot/policy selection clears
generation consent. Policies cannot be edited on existing keys; key replacement
is never implicit. Keys & access shows actual device-reported policies after
unlock, including unavailable/unknown values and a PIN Always limitation.
The PIV PIN label is bold. A persistent operation banner appears around hardware
private commands (including within the narrow details modal) and management
authentication. The native bold face is bundled DejaVu Sans Bold 2.37, unchanged
from the Nix dejavu-fonts package, with upstream license in assets/DejaVu-LICENSE.txt
(https://github.com/dejavu-fonts/dejavu-fonts/blob/version_2_37/LICENSE).
Its embedded font metadata also retains the copyright and license notices.
Always/Cached/Never guidance reflects reported policies. This reports a pending command, not a card-provided
touch-wait signal. It clears on completion/failure/lock and late events cannot
restore it after lock. No PIN is retained for these notifications.
Generic work and private-operation guidance share one progress row. While busy,
the row reserves space for wrapped policy guidance so repeated private commands
do not shift the controls below it; generic work does not suggest touching a key.
If setup fails after generating one key, that generated key remains. The current
UI refuses partial setup instead of guessing how to reuse an occupied slot.

Unlock verifies the PIN once; failures report remaining attempts and never retry.
PIN/management-key buffers are discarded afterward. Lock closes the session and
attempts bounded CCID power-off to clear volatile card authentication. Private
keys never leave the device; ECDH results, entry content keys and decrypted
payloads enter host RAM. This is hardware-backed key agreement, not on-card
decryption of individual passwords or on-card signing of stored passkeys.

Export a configured device's public participant JSON, then unlock an existing
wallet participant and enroll that JSON after comparing both fingerprints.
Enrollment grants the participant authority to sign subsequent wallet commits.
The Keys & access screen edits encrypted participant metadata entries referenced
by meta.entry, following root AGENTS.md. Names appear with fingerprints only
after unlock, and lock clears them and suppresses late name events. They are
excluded from credential lists. Names may be duplicated and confer no authority.
Enrolment grants all metadata entries to the newcomer. Revocation deletes the
departing participant's metadata and rotates the remaining metadata entries.
Unsaved naming is guarded during navigation and remote acceptance. Serial/slot
routing remains public for Connect. Firefox participant requests contain only
public keys; ignore any legacy browser recovery package in an old request.
Ordinary signed writes encrypt legacy name.json labels and prune browser.json.
Explicit encrypted history transfer for the extension is available through the store's
`browser_transfer` example; see `extension/firefox/GIT-OPERATIONS.md`.
It does NOT grant entry access. Use per-entry recipient selection to add grants
without rewriting the primary; use a new revision to remove recipients. Imports
have a separate, explicit recipient selection. Each new revision uses a fresh key.
Global revocation removes signing authority and rotates all affected entries in
one signed snapshot. It requires another participant that can decrypt every
affected entry; failure leaves the accepted wallet unchanged. It does not revoke
the lost device's ability to decrypt historical copies.

Physical validation so far covers USB discovery and PIN-free serial retrieval
on a connected YubiKey, using
`nix-shell --run 'cargo run -p kagitaba-device --example inspect_devices'`
(prints counts only). Protocol tests include
exact APDUs, PIN failure behavior, occupied slots, continuation, malformed replies,
and real envelope decryption/signature verification through a simulated PIV card.
Hardware setup/unlock/touch/removal must still be checked on the actual device.
Validate reconnect and backup-key round trips using synthetic entries before
relying on real credentials. Partial-provisioning recovery and changes to global
PIV PIN/management settings require explicit future work; never reset devices or
overwrite existing slots automatically.

## Persistence and trust

New wallets and backups are normal Git repositories with `.git`, an index, and
encrypted working files on the `wallet` branch. Creation accepts an empty folder
or an unused repository created by `git init` (only `.git`, unborn HEAD, no refs or
staged files); existing remote configuration is retained. Existing bare wallets
remain supported and are not converted automatically. Normal clones also work.
Logical files live in committed trees:
`kagitaba-format` (version 1), `participants/<id>/pub.pem`,
`participants/<id>/sign.pem`, `entries/<id>/primary`,
`entries/<id>/grants/<recipient-id>`. Public keys are SPKI PEM. The participant's
encrypted catalogue is `cache/<participant-id>/index`; its separately retained
wrapped key is `participants/<participant-id>/index-key`. No plaintext catalogue
is persisted. The accepted branch is `refs/heads/wallet`. See `../../INDEX-FORMAT.md`.

Unlock unwraps the participant's index key once and decrypts the catalogue. Missing
or stale rows are rebuilt from accessible entries; only new/changed own grants or
primaries require entry decryption. Cache-only and other-recipient grant changes
do not invalidate rows. The decoded index and key stay in the worker only while
unlocked; lock/close/replacement clears them. Titles, accounts and scopes go to the
UI as search hints, while opening/using a credential decrypts its authoritative
entry again. Native passkey matching uses a current index to skip unrelated RPs.

Genesis and native enrolment provision participant index keys. Index refreshes
batch with normal signed writes, or use a separate signed cache update after an
unlock/rebuild; a PIV touch may therefore be needed the first time. Unchanged
indexes do not cause another commit. A failed cache update retains useful session
rows and reports an advisory. Failed extraction removes the disposable own cache
from requested authoritative writes and falls back to readable titles; it never
regenerates an existing wrapped index key. Reader updates in browser and Android
must ship with these writers; older standalone clients reject the new paths.

Wallet reads always verify committed bytes, ignoring index and working-tree
contents. Writes and accepted updates refresh both the encrypted working files and
index. They require `wallet` to be checked out, refuse staged/unstaged changes,
conflicting untracked paths and symlinked wallet paths, and retain unrelated
untracked files. Git reference locks and `index.lock` protect updates; no external
Git process, hooks, or content filters are run by the app. Sparse/assume-unchanged
index entries and redirected index paths are unsupported. Files are replaced
atomically individually, but the whole checkout is not a filesystem transaction:
a crash or I/O failure can leave a partial working tree requiring manual recovery
from signed commits. Do not run concurrent Git mutations while the app is saving.
Tests use Git CLI only against synthetic temporary repositories for interoperability.

Single-file wallet containers are not implemented. Git bundles are standard
single-file object/ref archives, not writable repositories; ordinary Git cannot
push into one. A future container would need an app-managed extracted repository
and atomic repacking, while continuing to sync Git commits rather than the file.

Commits carry standard SSHSIG ECDSA-P256 signatures in `gpgsig`, independently
verified by Git/OpenSSH in tests. Genesis is pinned to a signing key. Every later
signer must appear in the preceding snapshot. ALL registered signers currently
have wallet-wide write authority; this is not a fine-grained sharing ACL. The
more complex per-participant ownership-signature policy was deliberately deferred.
Every commit is verified; unsigned/unauthorized commits, unsupported/conflicting
merges, changed primaries reusing a revision, stale writes and non-descendant
updates fail. Conservative two-parent merges follow the policy in root AGENTS.md:
one shared genesis/base, signer authorized in both parents, atomic entry/participant
three-way selection, exact merged bytes, and transitions checked from both sides.
Object hashes
are recomputed and sizes bounded. App data comes only from committed trees.

First open previews the untrusted genesis signing fingerprint for explicit user
comparison. Confirmation is bound to that exact key, not a mutable path alone.
Local trust records contain root SPKI and last accepted commit outside the wallet:
`$XDG_DATA_HOME/kagitaba/trust/<sha256-canonical-path>.json`, defaulting to
`~/.local/share/kagitaba/trust/`. Directories are 0700; records are 0600 and replaced
atomically after fsync. One native app instance is allowed per data directory to
prevent checkpoint-writer races. Moving a wallet requires another trust decision.
Loss of this local checkpoint loses rollback detection until a trusted checkpoint
is restored; signatures alone do not establish freshness.

Create encrypted backup copies into empty folders and pull updates from another
local wallet folder without decrypting secrets. Pull verifies the source history
before copying objects and again before compare-and-swap of the accepted branch.
Divergence can be combined with the explicit "Merge and sign" action if the root
policy finds no conflicts. The Backups & updates screen also offers merge from
a local folder or the cached origin/wallet ref. Unlock an existing signer
authorized on both sides. Conflicts leave the accepted branch/checkpoint unchanged;
no manual conflict editor or decrypted merge is implemented.
For metadata, missing grants are completed in a signed child after the clean
merge commit. Existing ciphertext and grants stay unchanged. Store::merge_then
prepares/verifies both commits before one accepted-head update, including for
local-folder and remote merge actions. Grant or either signature failure leaves
the branch/checkpoint unchanged. Native writes also complete missing metadata
grants after enrolment, following root AGENTS.md's merge exceptions.

Native transport uses the installed Git CLI, OpenSSH and coreutils `timeout`,
supplied by shell.nix, on a separate worker from hardware/wallet operations.
Opening a wallet and each 60-second interval fetch origin's wallet branch into
the untrusted remote-tracking ref. Fetch never advances the accepted wallet or
decrypts entries. Status counts are shown only after Store verifies the candidate
and shared genesis; stale results are discarded after local changes. Fetching
does not refresh the idle timer or block locking. The wallet header exposes
Fetch, Pull (behind), Merge and sign (diverged), or Push (ahead); accepting changes
requires saving/discarding UI edits first. Push is explicit, non-forced and pinned
to the reviewed local commit; it fetches/verifies first and refuses incoming
changes. A concurrent remote advance is rejected by Git. Failures are shown with
fixed non-secret messages; push failures survive later successful timer fetches.
Remote URL/authentication comes from existing origin configuration, configured
Git credential helpers and SSH agent/config. Transport disables Git hooks,
interactive prompts and ext helpers; SSH uses BatchMode. Timeout kills the
transport process group after 30 seconds (5-second kill grace). No new token
storage or remote configuration UI is provided. Git transport is outside the
Rust cryptography boundary and does not perform wallet signing/verification.

App backup copies retain original
signatures and never copy private keys or the device-local trust directory.

## Immutable file attachments

After Show more, saved entries have Attachments with Add file, Rename, Save as and Remove. Rename changes the encrypted display name
only, creating a signed primary revision while retaining the original attachment
blob and recipient set.
Files are immutable and owned exclusively by their parent entry; no sharing a file
between entries or inline file editing. Mutations require a clean saved draft and
sign immediately. New entries must be saved before adding files. Native authoring
is implemented in this checkout. Firefox and Android source readers/mutation
safeguards preserve compatible attachments, but do not provide this file picker
workflow; browser recipient reductions with owned files require the native client.
Installed artifacts are separate: the previously signed Firefox 0.1.2 XPI predates
attachment support and must not be treated as an upgraded reader.

Encrypted bytes live in the signed Git wallet under the owner's attachments path,
as specified in `../../ATTACHMENT-FORMAT.md`. Each file is bounded to 64 MiB and
has a fresh content key. Added files inherit the parent's existing recipients.
Reducing recipients or revoking a participant rotates every retained attachment's
key and blob revision along with the parent payload. Ordinary entry edits must
preserve the attachment manifest exactly; use dedicated Add/Remove actions.
Removing an entry prunes its blobs, while signed history retains historical copies.

Picker callbacks recheck the selected owner, parent digest and clean/unlocked UI;
the worker also checks the accepted wallet head and parent digest. Lock, entry
replacement and cancelled work invalidate the action token. Signing checks that
token before and after private operations. A signed write already completed when
cancellation arrives remains stored, consistent with other wallet operations.

Add and rekey stream one chunk at a time from disk/Git into private encrypted
staging. Snapshots retain lazy blob references rather than attachment bytes;
cloning a snapshot does not clone file contents. Save as streams plaintext into
a private temporary destination and verifies every chunk, total size, final hash
and EOF before publication. The worker publishes a mode-0600 file atomically and refuses to
replace an existing destination, even after a picker overwrite confirmation.
Choose a new name to export again. Plaintext export staging is in the selected
destination folder; encrypted add/rekey staging uses private temporary files.
Both are cleaned up on ordinary failure/cancellation. A process crash can leave
a private staging file. Encrypted staging and committed wallet files contain
ciphertext; plaintext export is written only to the chosen destination. No file
is opened automatically. Physical-key attachment validation remains pending.

## Imports and secret handling

Preview Firefox password CSV exports, unencrypted Bitwarden JSON, plaintext CXF or encrypted KeePass databases
(optional password component, including an empty password, and optional key file).
Every import is wrapped in a collection named after the source filename, with
existing collection trees embedded and their provenance preserved. The optional
Save original file as an entry checkbox is off initially and stores the unchanged
selected source file as an owned encrypted attachment, granted to the chosen import
recipients. It does not include a separate KeePass key file. The review defaults to
Skip N existing duplicates: exact readable item contents are compared, ignoring
newly generated IDs and attachment encryption randomness, while retaining source
provenance and unknown data. Verified equal attachments can match; unreadable
entries are counted without guessing their kind. Skipped copies link to existing
survivors and missing selected-recipient grants are added in the same signed update.

The review lists planned items and collections, with custom fields and preserved
source data available before import. Source account counts refer to CXF export
containers, not website logins. Custom-field counts count credential groups;
history warnings count source items with history, not historical revisions.
Preserved custom-field groups list distinct fieldType names and individual field
counts underneath the group total; labels and values are not included in that summary.
Detailed KeePass warnings identify the affected entry, known field, rejection
reason and next step. Inspect fields expands and scrolls to its masked preview;
source values are never included in diagnostic messages. Ordinary non-HTTP URL
strings remain catalogue data, with provider checks still required for use.
Choose recipients, then encrypt and sign. No import writes a plaintext intermediate.
Imported root collections remain atomic CXF payloads. Advanced JSON edits preserve
unknown fields and imported provenance. Original export files remain untouched.
KeePass active attachments are extracted separately from JSON and encrypted into
private staging before preview. Import publishes each file under its remapped
entry owner with the same recipients as the entry, in the same signed update.
Invalid names, missing owners and file limits fail explicitly; no partial import
is committed. Bitwarden/CXF external references without bytes remain omissions.
Opaque passkeys remain inactive source metadata. Preview values and source/history
JSON use zeroizing storage, reveal explicitly and are dropped on lock/navigation.

Operations run on a worker thread. UI clears its secret state on lock, after five
minutes without input, and when replacing the wallet snapshot. Results of pending
operations containing secrets are suppressed after a lock request; completed
wallet metadata updates still track the worker's accepted snapshot. Timeout
clearing is immediate even while the worker is busy; only the worker's explicit
lock completion releases suppression. A hardware operation already
submitted may finish before the queued lock; lock is not transaction cancellation.
Index decryption follows explicit unlock; decrypted rows are kept only in memory.
Current index refreshes reuse their authenticated ciphertext instead of encoding
and encrypting it again. A cold index still decrypts each accessible credential
once; a valid persisted index needs only its key unwrap. Bulk grant completion,
access changes and duplicate/import cleanup batch immutable wallet replacements.
Editor widget IDs include the
entry and replacement epoch; text undo state is discarded on entry/snapshot
replacement and lock. Encrypted entries can be selected and deleted even if
decryption fails; saving and grant changes require a decrypted payload.
Zeroization is best effort: egui, serde, clipboard/OS and upstream KeePass create
copies that do not all offer guaranteed wiping. Do not claim process-compromise
resistance or complete RAM/swap erasure.

SHA-1/256/512 TOTP generation is checked against RFC 6238 vectors. New passwords
use the shared configurable generator, defaulting to 12 lowercase/digit characters
with lookalike exclusions.
Changing a saved password never changes the password at the website.

Tests use synthetic credentials and temporary repositories. The optional `smoke`
feature enables eframe's screenshot-and-exit facility (`EFRAME_SCREENSHOT_TO`) for
virtual-display smoke tests; normal builds do not enable it. Use isolated temporary
XDG data directories and synthetic wallets for smoke tests. No source checkout
commits or staging are performed by development checks; temporary wallet histories
are created by tests.

With `smoke`, `KAGITABA_SMOKE_SCENE=home|wallet|attachments|index-preview|create|provision|touch|create-ready-new|create-created|enrollment|unlock|import|review|keys|transfer`
loads synthetic, disconnected UI fixtures (no hardware/credential reads or worker
writes). `KAGITABA_SMOKE_NARROW=1` selects a 440×780 viewport. Combine with
`EFRAME_SCREENSHOT_TO=/absolute/path.png` in a virtual display. These switches
are compiled out of normal builds. UI regression tests cover history opt-out,
favorites, verified-open routing, unsaved edits, late results on close, title
loading after unlock, and narrow details alongside the security regression suite.
`nix-shell --run 'bash tools/preview-ui.sh'` builds and captures these scenes under
Xvfb into `target/ui-preview/`, using temporary isolated XDG directories. Xvfb
must be available. Fixtures use fixed synthetic IDs for repeatable comparisons.

Remaining native product work includes the Android Kotlin/JNI client, PWA, OS
passkey authenticator and hosted Git transport. The separate Firefox client has
software passkey and HTTPS Git support. Collection membership and nesting
currently use the complete CXF editor; a dedicated collection organizer is not
implemented. Attachment handling and unsupported passkeys retain the documented
import limitations.

## Firefox native gateway

The normal Linux executable also acts as Firefox's native messaging host when
Firefox supplies its manifest path and `firefox@kagitaba.local` caller argument.
This mode runs before the GUI/instance lock and performs no wallet operations.
Register a built executable with
`uv run --no-project tools/install_native_host.py /absolute/path/kagitaba-app`.
This writes `~/.mozilla/native-messaging-hosts/kagitaba.json`; the manifest allows
only that extension ID. Development builds can use `target/debug/kagitaba-app`.
The native GUI must already be running with an open, unlocked wallet.

The GUI listens at `$XDG_RUNTIME_DIR/kagitaba/browser.sock`. Both the runtime
root and Kagitaba directory must be real, current-user-owned private directories;
the child is created 0700 and the socket is 0600. No /tmp or TCP fallback exists.
A held lock in the private directory prevents concurrent listeners even with
separate XDG data directories. Stale sockets are removed only after validating
type/owner/permissions and receiving ConnectionRefused. Other invalid paths fail
closed without disabling ordinary wallet use. The bridge validates the same
paths. Socket permissions isolate OS users, not hostile processes running as the
same user; caller arguments and claimed website origins are not cryptographic
browser attestation. Native UI approval remains required for every release.

Version 1 is a one-request connection: four-byte native-endian length followed
by UTF-8 JSON, bounded to 64 KiB in both directions. Request:
`{"version":1,"operation":"login","origin":"https://example.com"}`.
Success returns version, username and password; failure is a fixed error.
Only canonical HTTPS origins are accepted. The UI displays the origin, offers
entry selection and requires Approve and fill. The worker decrypts only that
entry and requires an exact HTTPS-origin match in CXF scope.urls, excludes
participant metadata and returns only the first basic-auth credential. It never
returns full payloads or keys.

The Native Messaging bridge relays frames unchanged, without JSON or operation
parsing. The native endpoint also accepts
`{"version":1,"operation":"passkey","origin":"https://example.com","kind":"create","input":{...}}`
(and `kind: "get"`), using the extension's base64url WebAuthn option encoding.
It independently validates RP suffix/public-suffix restrictions, challenge and
credential bounds and supported options. ES256 only; PRF, platform-only and
enterprise requests are unsupported. Native approval and a fresh single-attempt
PIV PIN verification precede each registration/assertion (UV); touch alone is not
UV. PIN failure clears the session. Matching accounts are decrypted on explicit
request; their labels and PIN drafts clear on cancellation/lock. Assertions use
zero counters and exact rpId matching. The app reuses kagitaba-browser's portable
ES256 primitives; passkey private keys stay native.

Registration encrypts a new CXF item for the current participant, completes
metadata grants and saves signed history plus trust before returning success.
Sharing with other participants remains explicit native wallet work. Cancellation
is checked before/after hardware operations and before/after signing. A signed
write already completed when cancellation arrives remains stored, but its response
is suppressed. There is no general list/edit API, TOTP or phone transport.

Requests expire after 90 seconds. Closing the native port propagates EOF to the
socket; cancellation/expiry, lock, wallet replacement and changed accepted heads
suppress pending responses. Secret worker results pass through the UI lock gate.
Requests do not refresh idle activity; explicit native approval does. Existing
zeroization limitations apply to JSON serialization and browser copies.

Synthetic tests cover framing bounds, exact-origin matching, private-directory
validation, exclusive listeners, real socket replies/disconnects/denials and
late secret suppression after lock, snapshot changes, cancellation and expiry.
Passkey tests encrypt registrations and independently verify assertion signatures,
RP binding, UV flags, zero counters, exclusions and cancellation. Device tests
exercise explicit PIN reverification failures and recovery. Physical PIV plus
browser/native approval still needs end-to-end hardware validation.


## Credential tools and field parity

See `../../FIELD-AND-GENERATOR-DESIGN.md` for the shared behavior. Header Tools
opens the standalone generator; each login supports Generate… and explicit
application to its draft. TOTP imports accept camera, PNG/JPEG and pasted URI,
reviewed before adding/saving. Linux camera capture uses ffmpeg on PATH, a bounded
local /dev/video stream and an in-memory preview; the project shell supplies it.
No camera is opened until explicitly requested. Locks and entry replacement clear
tool state and cancel scans. All data fields use bundled DejaVu Sans Mono.
TOTP storage permits positive u64 periods/digits; generation remains explicitly
limited to supported algorithms/digits. Ordinary URLs are never scheme-gated.

The Nix shell provides libdbus for rfd's dynamic portal backend and embeds its
runtime library path in local builds. An empty/disconnected native chooser result
clears the pending action and reports that selection was cancelled or unavailable.
Matching a saved participant on the unlock screen queues one-time PIN focus;
password dots use vertically centered text alignment. Header favorites sit directly
left of Close, sync state uses small muted text, and index preview values have
stronger hierarchy than labels and IDs.

Custom-field editing supports named `string`, `concealed-string`, and `boolean`
values. A label equal to PIN (case-insensitive, ignoring surrounding whitespace)
is concealed by default even when stored as `string`; reveal is explicit and
display policy never rewrites the stored field type. Edits preserve unknown field
metadata and unsupported field types. Boolean values remain CXF `"true"`/`"false"`
strings. Unknown fields remain available in the preserved payload.

## Collection navigation

See `../../COLLECTIONS-DESIGN.md`. All entries is the initial filter, followed by
Entries not in a collection and the readable collection tree. The participant
index supplies names, direct members and nested nodes; changing these filters
performs no read/decrypt command. Unfiled excludes membership across all readable
indexed nodes, including descendants; inaccessible collections cannot contribute
known membership. Missing/inaccessible/external links remain preserved and are
counted as unavailable. Edit collection explicitly opens the owning root record.
Lock and wallet replacement clear navigation selection. Wide screens use tree,
entries and details columns; medium screens retain tree/list with modal details;
compact screens use a collapsible tree above the list. Entry rows show cached
usernames and smaller muted abbreviated IDs, with the full ID available on hover.

Native discrete mouse-wheel scrolling uses 100 logical points per line (2.5×
egui's native default) across app views. Precise touchpad point deltas and
page-scroll input keep their original scaling.

Passkey details are readonly: RP, username/display name, credential ID and a
concealed, explicitly revealable user handle. Copy uses the normal timed clipboard
policy. Backup flags show their recorded values, or Not recorded when absent;
these labels do not infer registration state. ES256 / P-256 is shown only after
validating the stored PKCS#8 key as P-256; other keys display Unknown. The normal
view never displays the private key. Keys & access presents an unlocked device
as readonly name/serial, status and active slots; saved routing replaces the
Remember device action with a status label.

## Copy and duplicate cleanup

See `../../COPY-AND-DEDUPLICATION.md`. Tools exposes exact duplicate cleanup and
multi-entry copying between already trusted Kagitaba wallets. Destination keys
are independently verified, with a separate PIN unlock when the current key is
not enrolled there. Source-key authority never substitutes for target membership.
Source and destination hardware sessions are not held simultaneously during a
key switch. Copy review remains idle-lockable while only the target key is open.

Duplicate matching compares current credential content across importers. Known
source/history metadata and source timestamps are retained in a bounded encrypted
provenance archive when combining entries; unknown active data still participates
in equality. New provenance requires resealing the survivor to its complete union
of recipients. Exact reimports with no new provenance preserve primary bytes.
See COPY-AND-DEDUPLICATION.md for normalization and failure behavior.

## Manage access

Tools and Keys & access expose Manage access for an already enrolled participant.
Choose the participant, then preview all readable credential and collection entries:
new grants, already granted, and unavailable. Grant access and sign adds the
previewed grants in one signed update, preserving primary records, existing grants,
and attachment blobs. It does not revoke access or provision a device. Participant
metadata retains its existing all-participants policy. The backend binds review to
wallet head, current key and target; stale review is refused. Target changes,
navigation, wallet replacement and lock discard review; late preview events are
ignored. Synthetic tests cover atomic grant preservation and review lifecycle;
physical-key validation remains pending.

Entry summaries and decrypted details show Collections with one root-to-node
path per direct membership, derived from readable collection index hints. Ancestor
names provide the path, not implied parent membership. Multiple roots and nested
memberships are retained; inaccessible collections are not inferred. This display
requires no additional key operation and does not authorize access.

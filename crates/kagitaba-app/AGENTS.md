# Native application

Run from the workspace: `nix-shell --run 'cargo run -p kagitaba-app'`.
This is the Linux prototype; PWA is not implemented. Android is documented in
`../../android/AGENTS.md`. The separate
standalone Firefox client is documented in `../../extension/firefox/AGENTS.md`.
Preserve the existing password-manager backup while testing. Importing a passkey
into this native application is storage, not registration as an OS authenticator.

## Design pattern

Rectangular controls, near-black background, dark blue surfaces, pale text and
cyan primary actions. Readable 16px body text, hairline separation and
no rounded corners or shadows. `theme.rs` owns the visual language.
Android and Firefox share these roles and task-focused navigation. Keep copy
concise, retaining instructions needed for trust, access and destructive actions.

The welcome screen contains Open wallet, Create wallet, the opt-in Remember opened
wallets checkbox, then favorites above recent wallets. Stars toggle favorites;
the X removes only a saved location, never wallet files or trust records.
Disabling history immediately clears recents, including persisted recents.
Explicit favorites survive history opt-out. Only successfully verified/opened
wallets enter history; recents are deduplicated, newest first, capped at 20.
Navigation preferences live in `$XDG_DATA_HOME/kagitaba/navigation.json` (0600,
atomic replacement), with the usual `~/.local/share` fallback. They contain only
paths/preferences, never credentials, titles, PINs or trust decisions. Linux path
bytes are hex encoded to preserve non-UTF8 paths; this is not encryption.

Opening chooses a folder, verifies trust/history, then offers detected or manual
participant/device/slot selection. Unlock & load entry names explicitly decrypts
titles into memory. A locked wallet can browse encrypted IDs and make backups.
Create chooses a folder first, prepares a key, then explicitly creates/signs.
The wallet workspace has an entry list on the left and details on the right;
below 780pt available width, details use a scrollable modal with Close and Lock.
Import (source, preview/recipients, completion), Keys & access, and Backups & updates
are separate screens with Back. Lock remains available during work and in the
details modal. Closing a wallet waits for the worker to drop its store and session.
Unsaved entry edits prompt before navigation; locking always clears immediately.
New entries initially select only the current enrolled participant. Enrollment
does not imply entry access. Raw CXF editing remains an explicit advanced option.

Password/note values are masked with per-field Show/Hide controls. Copy buttons
expire their clipboard contents after 30 seconds only if
the contents still match. Manual selection/copy in the advanced editor and system
clipboard history are outside that guarantee. Complete CXF JSON is an explicit reveal/edit panel for unsupported
fields, provenance and collection links. No external resource URLs are fetched.
File dialogs render in process using egui-file-dialog; no external dialog command.

## Hardware workflow

Requires a YubiKey with PIV and metadata support (5.3+). FIDO-only Security Keys
cannot implement this PIV backend. USB CCID is accessed directly using Rust nusb;
no ykman, libusb, PC/SC or OpenSSL is linked or spawned by the application.
OS windowing, graphics, clipboard and USB interfaces remain platform boundaries.
Other programs holding the CCID interface must release it. USB permissions are
provided by the OS; the app never changes system rules or detaches another owner.

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
`entries/<id>/grants/<recipient-id>`. Public keys are SPKI PEM. No combined catalog
or plaintext title cache is persisted. The accepted branch is `refs/heads/wallet`.

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

## Imports and secret handling

Preview unencrypted Bitwarden JSON, plaintext CXF or encrypted KeePass databases
(optional password component, including an empty password, and optional key file), review non-secret warning categories, choose
recipients, then encrypt and sign. No import writes a plaintext intermediate.
Imported root collections remain atomic CXF payloads. Advanced JSON edits preserve
unknown fields and imported provenance. Original export files remain untouched.
Attachments are not copied, and opaque passkeys remain inactive source metadata.

Operations run on a worker thread. UI clears its secret state on lock, after five
minutes without input, and when replacing the wallet snapshot. Results of pending
operations containing secrets are suppressed after a lock request; completed
wallet metadata updates still track the worker's accepted snapshot. Timeout
clearing is immediate even while the worker is busy; only the worker's explicit
lock completion releases suppression. A hardware operation already
submitted may finish before the queued lock; lock is not transaction cancellation.
Title decryption is explicit and kept in memory. Editor widget IDs include the
entry and replacement epoch; text undo state is discarded on entry/snapshot
replacement and lock. Encrypted entries can be selected and deleted even if
decryption fails; saving and grant changes require a decrypted payload.
Zeroization is best effort: egui, serde, clipboard/OS and upstream KeePass create
copies that do not all offer guaranteed wiping. Do not claim process-compromise
resistance or complete RAM/swap erasure.

SHA-1/256/512 TOTP generation is checked against RFC 6238 vectors. New passwords
use 24 uniform random characters from a 64-character alphabet (144 random bits).
Changing a saved password never changes the password at the website.

Tests use synthetic credentials and temporary repositories. The optional `smoke`
feature enables eframe's screenshot-and-exit facility (`EFRAME_SCREENSHOT_TO`) for
virtual-display smoke tests; normal builds do not enable it. Use isolated temporary
XDG data directories and synthetic wallets for smoke tests. No source checkout
commits or staging are performed by development checks; temporary wallet histories
are created by tests.

With `smoke`, `KAGITABA_SMOKE_SCENE=home|wallet|create|provision|touch|unlock|import|review|keys|transfer`
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

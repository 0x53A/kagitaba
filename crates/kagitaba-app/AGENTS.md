# Native application

Run from the workspace: `nix-shell --run 'cargo run -p kagitaba-app'`.
This is the Linux prototype; Android, PWA and browser passkey authentication are
not implemented. Preserve the existing password-manager backup while testing.
Importing a passkey is storage, not registration as an OS/browser authenticator.

## Design pattern

Rectangular controls, charcoal surfaces, signal-orange title/selection, readable
15px body text and explicit operations. Two columns: device/wallet/import controls
on the left, entry browsing and editing on the right. Password/note values are
masked. Copy buttons expire their clipboard contents after 30 seconds only if
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

Setup explicitly generates P-256 keys in retired PIV key-management slots 0x82
(ECDH) and 0x83 (ECDSA signing). It checks BOTH slots first, refuses occupied or
unreadable slots, and never resets the device. No certificates are written;
public keys are read through PIV metadata. Existing PIN and management-key values
are supplied by the user; global PIN/management key are not changed automatically.
The factory-management-key button is explicit, not an automatic fallback.
Management authentication supports TDES and AES-128/192/256 according to metadata.
Encryption uses PIN-once/touch-cached; signing uses PIN-once/touch-always.
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
It does NOT grant entry access. Use per-entry recipient selection to add grants
without rewriting the primary; use a new revision to remove recipients. Imports
have a separate, explicit recipient selection. Each new revision uses a fresh key.
Global revocation removes signing authority and rotates all affected entries in
one signed snapshot. It requires another participant that can decrypt every
affected entry; failure leaves the accepted wallet unchanged. It does not revoke
the lost device's ability to decrypt historical copies.

No physical YubiKey was connected during implementation. Protocol tests include
exact APDUs, PIN failure behavior, occupied slots, continuation, malformed replies,
and real envelope decryption/signature verification through a simulated PIV card.
Hardware setup/unlock/touch/removal must still be checked on the actual device.
Validate reconnect and backup-key round trips using synthetic entries before
relying on real credentials. Partial-provisioning recovery and changes to global
PIV PIN/management settings require explicit future work; never reset devices or
overwrite existing slots automatically.

## Persistence and trust

Wallet folders are bare Git repositories. Logical files live in committed trees:
`kagitaba-format` (version 1), `participants/<id>/pub.pem`,
`participants/<id>/sign.pem`, `entries/<id>/primary`,
`entries/<id>/grants/<recipient-id>`. Public keys are SPKI PEM. No combined catalog
or plaintext title cache is persisted. The accepted branch is `refs/heads/wallet`.

Commits carry standard SSHSIG ECDSA-P256 signatures in `gpgsig`, independently
verified by Git/OpenSSH in tests. Genesis is pinned to a signing key. Every later
signer must appear in the preceding snapshot. ALL registered signers currently
have wallet-wide write authority; this is not a fine-grained sharing ACL. The
more complex per-participant ownership-signature policy was deliberately deferred.
Every commit is verified; merges, unsigned/unauthorized commits, changed primaries
reusing a revision, stale writes and non-descendant updates fail. Object hashes
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
Divergence requires explicit future merge support; neither side is discarded.
Network GitHub/GitLab fetch/push is not implemented. `Store::accept` can validate
objects already fetched by a future transport. App backup copies retain original
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

Remaining product work includes the Android Kotlin/JNI client, PWA, browser/OS
passkey authenticator and hosted Git transport. Collection membership and nesting
currently use the complete CXF editor; a dedicated collection organizer is not
implemented. Attachment handling and unsupported passkeys retain the documented
import limitations.

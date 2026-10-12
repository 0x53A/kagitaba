# Android JNI adapter

Read root AGENTS.md and `android/AGENTS.md`. Reuses `kagitaba-browser::execute`
for portable Rust crypto and `kagitaba-store::Store` for native signed Git storage.
The Kotlin application owns Keystore, platform caller validation, entropy,
transport, file paths, UI, session lifetime and trusted checkpoints.

The JNI entry point accepts bounded UTF-8 JSON and caller-supplied SecureRandom
bytes. It returns JSON bytes or fixed non-secret exceptions; no logging. The
JNI export uses Rust 2024's unsafe(no_mangle) attribute. No raw pointer operations
are implemented here; the jni crate owns JNI access. This application boundary
does not weaken the portable core's forbid(unsafe_code).

PIV mode uses `openPiv` with a bounded PIN/slot request and an Android raw-APDU
transport callback. Rust reuses `kagitaba-device` without its native USB feature.
Process-local `piv:<handle>` identities refer to authenticated hardware sessions,
never exported private scalars. Lock removes the handle and closes the Android
connection. Each open verifies PIN exactly once; no automatic retry. Errors are
fixed strings including explicit remaining-PIN-attempt messages. Only the
foreground UI opens sessions. Existing software identity APIs are retained but
the Android application no longer selects them. Store operations accept a shared
Signer interface; PIV ECDH opens existing CXF grants and PIV ECDSA signs commits.
Git tokens are Rust-encrypted and wrapped to the hardware recipient using a
separate, versioned application-owned local envelope (see android/AGENTS.md).

The same bridge supports PIN-free `inspect` (verified wallet candidates) and
`inspect_slots` (new-wallet provisioning). Match actual encryption AND signing
keys; hints route discovery but cannot authorize it. `provision` requires explicit
confirmation, selected serial and two slots proven empty before any writes, then
uses the native management authentication/generation implementation. Never retry
failed PINs or overwrite slots.
`provision` accepts separate `encryptionPolicy`/`signingPolicy` objects with
numeric `pin` (1 Never, 2 Once) and `touch` (1 Never, 2 Always, 3 Cached).
Omitted policy objects use existing defaults; invalid/unsupported choices fail
before hardware mutation. Slot discovery, matched participants and opened
sessions expose actual device policy bytes, including unknown values, or null
when unavailable. These are display metadata, not signed routing hints.
The session observer calls the kept `PivConnection.setTouchPending(int)` method
around private commands: reported touch byte while pending, -1 on completion;
0 means unavailable. Notifications contain no secrets and do not prove that a
card is currently waiting for touch. Store snapshots expose public `devices` and
`signingKeys` for clone-before-unlock routing, and creation persists the selected
device hint in the signed genesis. Kotlin isolates each wallet's storage/trust.

`store_create`, `store_connect`, `store_open`, `store_accept`, `store_save`,
`store_delete`, `store_export`, `store_import`, `store_name_participant` operate only on the app's private
Git directory. Open/updates require pinned root and checkpoint. `store_connect`
is the explicit first-use exception, inferring then verifying the genesis signer.
Returned snapshots contain encrypted records/public metadata. Decryption happens
separately and only after verified snapshot loading. Saves accept canonical
primary/grant records, validate associations/transitions and sign with the
software participant's independent signing scalar. Imported old history never
replaces a newer accepted checkpoint.

`store_name_participant` takes `participantId`, encrypted `primary`/`grants`, and
the unlocked `identity`. Kotlin opens the existing metadata with metadata_decrypt
(including PIV support), then uses metadata_encrypt to retain unknown fields and
grant all participants. The store checks entry identity and the complete grant
set and persists meta.entry and encrypted records together. Returned snapshots
contain only `participantMetadata` pointers; Kotlin decrypts names after unlock.
Ordinary credential writes cannot overwrite/delete metadata entries. Writes
encrypt legacy public names and prune browser recovery packages, using injected
entropy. Historical commits remain verifiable.
Store errors map to distinct static, value-free messages; the Kotlin allowlist
must be kept aligned, and raw native/Git errors must never be exposed.

Use synthetic native tests to verify interoperability, tampering, unauthorized
signers and rollback. Keep all passkey cryptographic operations in the portable
adapter rather than creating a second Android-only format or implementation.

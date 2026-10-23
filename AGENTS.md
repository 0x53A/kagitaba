# Kagitaba

Personal credential wallet. Rust workspace containing the in-memory `kagitaba-core`,
`kagitaba-cxf` schema/import library, `kagitaba-device` USB/PIV adapter,
`kagitaba-store` signed Git persistence and `kagitaba-app` Linux GUI. Real credentials
are not fixtures; physical-device validation is still pending. Applicable parent
`AGENTS.md` instructions also apply. Do not stage,
commit, initialise a Git repository, or change the parent repository's state
without explicit instruction.

## Boundaries and design pattern

1. `crypto`: opaque bytes, public/private key operations, caller-supplied context
   and randomness. No entries, files, paths, storage, Git, network, OS key stores,
   credential fields, clock, prompts, or executor. All linked crypto is Rust.
2. `wallet`: immutable logical snapshots of participants, primary records, and
   detached grants. Bodies are opaque. A primary can be encrypted credentials or
   application-specific retrieval metadata. This layer does not assume that its
   body can be decrypted by the local crypto module. Zero grants are legal for
   other retrieval backends. Structured validation is not authentication.
3. Applications: Linux native client, standalone Firefox extension, and Android
   Kotlin/JNI client (see `android/AGENTS.md`). Own file layout, trusted-key enrolment, signing, sync, schema,
   caches, imports, random sources, hardware access, and interpretation of bodies.

Rust WASM compatibility is a requirement for a later PWA. Core randomness is
injected via `TryCryptoRng`; core dependency features that would acquire OS
randomness are disabled. The optional upstream KeePass adapter can use platform
randomness internally. Hardware operations are async, with no `Send` bound or
runtime dependency. Crate forbids unsafe code; dependencies have their own audit
boundaries. No claim that all dependency internals are free of unsafe Rust.

Immutable owned attachments use application-level chunk encryption while keeping
the core ciphertext limit unchanged. See `ATTACHMENT-FORMAT.md`. Mutable objects
and remote attachment storage remain out of scope. Revocation must re-encrypt
retained attachments with fresh keys and blob IDs; rotating only the descriptor
would not revoke a retained attachment key.

## Agreed storage and lifecycle (application-owned)

Proposed eventual layout:

```
participants/<key-id>/pub.pem
participants/<key-id>/<optional participant metadata>
entries/<entry-id>/primary
entries/<entry-id>/grants/<key-id>
```

Owned attachment ciphertext lives at `entries/<entry-id>/attachments/<blob-id>`.
Each file belongs to exactly one entry; there is no shared attachment pool. Its
name, size, hash and key live in a file credential inside the encrypted primary.
The whole entry directory is one merge unit. An attachment change requires a new
primary revision; removing a recipient also replaces all retained attachment
blobs. Signed readers reject attachment paths without an owner and retained old
blob IDs after a grant reduction. Applications check the decrypted descriptor/blob
membership when opening entry details or using files. Native opening validates
signed paths and object headers; container
validation and object hash verification occur when attachment contents are used.
Newly staged containers are checked before commit. Historical recipients retain historical access.
Limits are 64 MiB plaintext per file, 128 files per entry, 256 MiB per snapshot
and 512 MiB of reachable transfer objects. These remain resource bounds. Native/store snapshots retain Git object IDs and
sizes for attachments; opening, indexing and searching do not load their bytes.
Explicit file access streams through bounded buffers and private staging files,
including loose and packed/delta Git objects. Native add/export/revocation use
1 MiB crypto chunks. JSON browser/JNI transfer bridges remain buffered; the store
also exposes a streaming transfer writer. Older readers that reject
attachment paths must be upgraded before opening wallets containing attachments.
Firefox 0.1.3 has been built, signed and validated with attachment-bearing
native/browser round trips. The previously signed Firefox 0.1.2 XPI predates
attachment support; installed clients must be upgraded before sharing
attachment-bearing wallets with them.

Public keys use canonical DER SubjectPublicKeyInfo, optionally PEM `PUBLIC KEY`.
The key ID is lowercase hex SHA-256(canonical DER), not a hash of the PEM text.
Version 1 supports P-256 key agreement only; reject other algorithms explicitly.
Entry IDs and revision IDs are independent random 16-byte values (32 hex digits).
There is no mandatory wallet ID or global manifest. Catalogue/search indexes are
reconstructable app caches. Public key registration alone grants no entry access.

Optional participant metadata is an ordinary encrypted entry. Its public pointer
`participants/<key-id>/meta.entry` contains the canonical 32-hex entry ID plus LF.
Pointers must reference existing entries, belong to enrolled participants and be
unique. The encrypted UTF-8 JSON object has `format: "kagitaba-participant-metadata"`,
`version: 1`, `entryId`, `participantId`, and optional `name`. Both IDs are bound
and checked after decryption. Application schema lives in kagitaba-cxf alongside,
but separate from, CXF payloads; the opaque core has no metadata semantics.
JSON is limited to 16 KiB, rejects duplicate members and preserves unknown fields.
Names allow 128 Unicode scalar values / 512 UTF-8 bytes, no surrounding whitespace,
controls or bidi override/isolate controls. Clearing a name preserves the entry
and other metadata. Names are display hints; always show a fingerprint too.
Metadata entries are excluded from credential lists/providers and decrypted only
after unlock; lock clears names and suppresses late name results.

Metadata is granted to all participants. Enrolment adds missing grants without
rewriting primary or existing grant bytes. Revocation deletes the departing
participant's metadata and rotates remaining metadata with the other affected
entries. Historical names remain readable to historical recipients. Public
YubiKey serial/slot routing stays in device.json for Connect. Browser unlock
parameters and its encrypted software identity remain installation-local and
are omitted from participant requests and exports. Reinstallation creates a new
participant; no same-identity recovery flow. Legacy name.json/browser.json remain
readable for signed-history compatibility; ordinary app writes encrypt legacy
names and prune browser.json. Historical commits are never rewritten.

Each encrypted content revision gets a fresh random 32-byte content key and a
fresh revision ID. Each authorised participant gets a detached wrapped copy of
that same content key. All grants bind the exact primary record's digest.
Adding a recipient requires one existing participant's private operation and the
new public key; it leaves the primary and existing grants byte-for-byte unchanged.
An entry update produces a new primary and a complete matching grant set.
Removing a grant alone does not revoke access; rotate the key and ciphertext and
omit the removed participant. Old snapshots remain readable by their recipients.
The opaque middle layer cannot prove that an app used a fresh encryption key;
it enforces revision changes and grant associations, not plaintext semantics.

The app accepts signed history descending from an already trusted snapshot,
including explicitly created conservative two-parent merges. Verify committed
bytes and authorize every signer; mathematical signature validity alone is not
enough. Both branches must share the exact genesis and have one unambiguous merge
base. Reject unrelated roots, redundant/duplicate parents, octopus merges and
criss-cross histories with multiple best bases. A merge signer must be enrolled
in BOTH parent snapshots. Verify every reachable commit and accept a checkpoint
on either ancestry path; no rebase, force push or checkpoint reset is needed.

Three-way merging treats each entry (primary plus complete grant set) and each
participant (encryption/signing keys plus device metadata and meta.entry) as an atomic
unit of committed bytes. One-sided or identical changes combine; different
concurrent changes, including edit/delete, conflict. A collection tree remains
one entry. Deletions are preserved; no field-level credential merge, credential grant union,
timestamp winner, or automatic conflict resolution. Validate the resulting
snapshot and revision transitions against BOTH parents. Received merge commits
must contain exactly this result; an authorized signature does not excuse a
merge dropping or adding changes. A stale grant is never copied onto a new
revision. This history policy belongs to applications, not the opaque core.
Participant metadata has a narrow exception: independent additive grants merge
when the base primary and grants are unchanged. A new metadata revision concurrent
with only additive grants takes the new revision and its matching grants; obsolete
grants are never carried over. Competing revisions and removals conflict. When
both sides add different randomized wrappers for the same recipient, omit that
grant from the clean merge and recreate it in the follow-up. A merged metadata pointer cannot dangle or
leave its old metadata entry orphaned. New membership can leave metadata missing
grants in the clean merge snapshot: this intermediate commit is valid. Native
merge then adds missing grants in a separate signed child commit, preserving the
clean merge bytes. Prepare and verify both commits before one accepted-head
update; grant/signing failure publishes neither. If no grants need adding, no
extra commit is needed. All clients verify both commits normally.
Native merge creation requires an explicit action and signing; ordinary updates
only accept verified descendants. Firefox and Android accept these merged
histories; their automatic sync still refuses to create a merge on divergence.
Bootstrap trust/rollback handling and semantic conflict UI remain app work.
Optional master recipients, per-participant ownership signatures, proxy
re-encryption, and standalone authorisation records are deferred.

## Participant index design and implementation

The native client implements this index through `kagitaba-store::index`.
See `INDEX-FORMAT.md` for the exact versioned encoding, extraction rules, bounds
and failure behavior. Firefox/Android Rust readers and the Firefox JavaScript
history verifier accept and preserve the new paths; browser listing still uses
its existing flow.

Persist each participant's reconstructable encrypted index at `/cache/<p>/index`
(paths are wallet-root-relative). The repository holds the index and its wrapped
key so they travel with clones, backups and sync. Entries and grants remain
authoritative; a missing index is rebuilt by its participant after unlock.
Listing should decrypt the index once, then decrypt individual entries only when
opened/used or when their index rows need rebuilding. Index rows contain entry
IDs, primary digests, titles, account/usernames, URLs/scopes and presence flags
for password, TOTP and passkey credentials. Support multiple usernames/scopes;
presence does not imply that a preserved credential type is supported for use.
Collection rows also cache their nested hierarchy and direct local item links for
collection navigation without additional entry decryption. See
`COLLECTIONS-DESIGN.md` for filter and access semantics.

Generate one random index key per participant, wrap it exclusively to that
participant, and persist the wrapper outside the disposable cache
at `participants/<p>/index-key`. Provision and sync this key before independent
rebuilds; independently generated keys cannot produce identical indexes. The key
belongs to authoritative participant metadata and is removed on revocation.
Cache invalidation must not delete or regenerate it. Use AES-SIV deterministic
authenticated encryption (RFC 5297) in a separate versioned cache format; do not
fix nonces or alter the existing entry/wrapped-key wire formats. Canonical
plaintext and associated data must produce identical bytes across clients for
the same key and relevant snapshot. Specify extraction rules, ordering,
serialization and schema version; exclude timestamps and machine-specific data.
Identical ciphertext deliberately reveals equality of index versions.

Use a fingerprint of canonical sorted relevant snapshot data (entry IDs, primary
digests and this participant's grants), computed from the verified snapshot,
instead of embedding the current Git commit as the validity marker. Unrelated
commits and cache-only commits must not invalidate the index or trigger write
loops. Newly accessible entries and changed accessible primaries require
decryption; deleted entries or removed own grants drop rows without decryption.
Changes to the participant's own grants must be detected; changes only to other
participants' grants do not require rebuilding rows. Persist refreshes through
normal signed writes/sync, batching with ordinary updates where possible; PIV
signing can still require a touch. External trust checkpoints remain necessary.

Merge each `/cache/<p>/` tree independently of authoritative participant metadata.
Preserve one-sided or identical changes. Different concurrent changes, including
edit/delete, omit that participant's entire cache tree from the merged snapshot.
Removed participants have no cache in the result. Historical commits remain
unchanged. This is a deterministic merge-verification rule for received commits
as well as locally created merges; cache conflicts never block a merge, while
authoritative data keeps its existing conflict rules. All current wallet readers
support these paths; older clients that reject unknown paths must be updated before opening index-bearing wallets. The current v2 cache encoding
and bounds are specified in `INDEX-FORMAT.md`. Version 1 caches rebuild after unlock
to correct empty-password presence flags; participant index-key wrappers are unchanged.

## Future Linux passkey provider

An application-owned `/dev/uhid` CTAP2 authenticator could expose native wallet
passkeys to Firefox and Chromium without a passkey browser extension. With a
physical YubiKey present, select Kagitaba first, let the browser cancel its device
selection request to the physical key, then request the PIV touch for decryption.
Test this ordering so unlocking the wallet does not select the wrong website
authenticator. This is a design note, not implemented Linux functionality.

## Application payload schema and CXF import

Follow FIDO CXF 1.0 where reasonable, using the Proposed Standard with errata:
https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html
Reuse its Item, credential, Collection and LinkedItem structures in a versioned
Kagitaba application envelope. Individual payloads are not complete CXF export
documents; full export/import requires the standard Header/Account packaging.
Keep these application types outside the opaque crypto and wallet layers.
The separate `crates/kagitaba-cxf` crate implements this boundary using
`credential-exchange-format` 0.4.0 (MIT, Bitwarden) for upstream typed models.
Preserved JSON is authoritative: typed reserialization can discard unknown fields.

Collections are encrypted entry payloads with their own grants. Their names and
membership stay encrypted. A collection link is organisational only: it neither
grants access to the target nor causes its secrets to be decrypted automatically.
Missing or inaccessible targets are allowed and must not be silently discarded.
Editing an item does not require rewriting a collection that references it.

CXF LinkedItem contains `item` (base64url-encoded opaque item ID) and optional
`account` (account ID), NOT a URL. Local links resolve by stable identity within
the current wallet. Use the entry's existing 16 ID bytes encoded as base64url for
native CXF item IDs; disk names remain hexadecimal. Import must map IDs and
rewrite references together, preserving unresolved/external references rather
than treating them as filesystem paths or network locations.

CXF `subCollections` embeds child Collection objects, not links. Preserve that
shape initially: one root collection entry can contain a nested collection tree;
the tree shares that entry's grants. Independently encrypted child collections
would require an explicitly documented extension, not a change to LinkedItem's
meaning. Collection IDs and item IDs must be unique within the exported account.
There may be zero or more root collections. Each root and its embedded descendants
form one atomic update unit: an edit creates a fresh entry revision, content key,
and matching grants. Different roots are independent entries. Logical merging of
concurrent edits to the same root requires explicit application support; initial
history handling rejects such conflicts. Items may exist outside collections.

Application plaintext envelope (fully encrypted inside a core Ciphertext):

```json
{
  "format": "kagitaba-cxf",
  "version": 1,
  "cxfVersion": {"major": 1, "minor": 0},
  "kind": "item",
  "entity": {"id": "base64url-entry-id", "title": "Example", "credentials": []}
}
```

`kind` is `item` or `collection`. The illustrative ID above must be replaced by
the base64url encoding of the entry's actual 16 bytes. Imported envelopes also
contain encrypted `source` metadata: original header (without accounts), original
account metadata (without items/collections), and original root/item ID. Native
payloads need no source metadata. Unknown envelope/entity members are preserved.
Payload parsing verifies the inner ID against the outer entry ID. Major versions
other than 1 fail explicitly; additive CXF minor versions are retained.

`Document::from_json` / `from_reader` accept plaintext CXF bytes/file streams.
`Document::to_json` preserves unsupported fields, credential kinds, and exact JSON
numbers (but not original whitespace/key order). `plan_import` allocates fresh
local IDs and rewrites standard collection links and item-reference credentials
across all imported accounts. Embedded collection IDs are remapped too. Missing
targets retain their original item/account IDs and stay unresolved; this does
not fetch anything or resolve them against unrelated local IDs. Unknown vendor
extension references cannot be rewritten and remain opaque in their original
namespace. The original Document remains available for lossless source export.

`ImportPlan::encrypt_into` requires explicitly selected, already registered
recipients, creates fresh content keys/revisions/grants, and returns a new Wallet
only after all entries succeed. No existing entry is overwritten. Reimport is an
explicit new copy, not deduplication. The plan's report counts unresolved links,
opaque credential types/unknown TOTP algorithms, and external file credentials.
No attachment bytes are fetched or imported; file descriptors are retained only.
Empty accounts are counted but create no wallet entry. Their metadata remains in
the original Document. Neither import nor schema operations write files or Git.

Limits: 32 MiB exchange input, 1 MiB serialized per-entry envelope, JSON nesting
64 and collection depth 32 (the JSON limit may be reached first). Duplicate JSON
member names and duplicate account/entity IDs fail explicitly. ID comparisons
use decoded bytes, not base64 text. TOTP base32 is validated; passkey keys must be
structurally valid PKCS#8 DER. This is storage/import, not an authenticator or a
full semantic validator for every credential kind/algorithm. Unsupported types
must not be activated merely because they were preserved. Future passkey usage
must implement CXF's zero-counter requirement and enforce each passkey's rpId.

SecretJson wipes retained strings on drop; serialized output uses Zeroizing.
Parsing and upstream validation create temporary allocations that are not all
zeroized. `Document::typed()` explicitly returns caller-owned upstream copies
which have Debug and no zeroization: never log these views or raw JSON. Our
Document, Payload and ImportPlan deliberately have no Debug/Clone. Errors contain
no input values. This is best-effort memory hygiene, not complete memory erasure.

CXP is NOT yet implemented: encrypted ExportResponse objects return
`CxpSessionRequired`. FIDO's currently linked public CXP working draft is
https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html
Its archive/JWE and HPKE response description differs from the current upstream
Rust protocol models. Need the exporting app/platform and exchange profile/session
before implementing an interoperable decoder; do not invent a wire format.
CXF schema/import is independently usable regardless of that transport decision.

## Bitwarden and KeePass import adapters

`kagitaba_cxf::bitwarden::from_json` / `from_reader` accept unencrypted Bitwarden
JSON exports (personal and organisation). CSV and encrypted JSON are unsupported.
`kagitaba_cxf::keepass::from_bytes` / `from_reader` accept encrypted databases with
an optional password and optional key-file bytes; enable the `keepass` feature.
Both key components are combined when supplied. `from_database` accepts an already
unlocked upstream database. Hardware challenge-response composite keys are not
supported. The Rust `keepass` parser supports KDBX3/4 and legacy KDB; our integration
tests currently exercise KDBX4 with password and raw key file.

Both return `Conversion`: review `report()` then use `document().plan_import(...)`
and `ImportPlan::encrypt_into(...)`. No paths, prompts, persistence or Git operations
are introduced. These are library adapters, not an import GUI. Bitwarden folders
and organisation collections become separate roots; KeePass's root group becomes
one root collection with embedded nested groups. Stable source IDs are hashed into
distinct namespaces; the existing import planner allocates fresh wallet-local IDs.
The synthetic CXF header uses timestamp zero (unknown), not the current time.

Login fields, notes, custom fields and standard TOTP seeds/URIs map to CXF.
KeePass `TimeOtp-Secret` (UTF-8), `-Hex`, `-Base32` and `-Base64` map to active
TOTP with `TimeOtp-Length`, `TimeOtp-Period` and `TimeOtp-Algorithm` settings.
Defaults are six digits, 30 seconds and HMAC-SHA-1; SHA-256/512 are supported.
Only locally usable six-to-eight-digit configurations activate. Invalid or
ambiguous settings, unknown TimeOtp fields and unresolved references retain their
custom fields with an OTP warning. Successfully mapped fields remain in encrypted
source provenance but are omitted from redundant custom-field credentials.
Equivalent `otp` and TimeOtp configurations deduplicate; distinct ones are retained.
Mapping reference: https://keepass.info/help/base/placeholders.html#otp
KeePass `KP2A_URL_<number>` web URLs join the entry scope, with duplicate URLs
removed and the primary URL first. Non-web/credential-bearing URLs remain custom
source data with a matching-policy warning. Ordinary supported custom fields are
editable across clients and no longer count as unknown credentials; PIN-labelled
strings default to concealed UI without changing their stored type.

KPEX passkeys map to active CXF credentials only for valid P-256 PKCS#8 PEM,
base64url credential/user IDs and a valid RP domain. Missing KPEX BE/BS flags
default individually to false for legacy imports; explicit values are preserved.
Malformed or inconsistent flags, PRF/counter/unknown passkey extensions and
unsupported algorithms remain preserved with warnings. Imported credentials carry the
application extension `kagitabaBackupFlags: {eligible: bool, state: bool}`;
BS=true requires BE=true. All providers copy these flags from the credential,
never the site's request, into signed authenticator data. Absent flags retain
legacy behavior (BE=true, BS=false); malformed flags make the credential unusable.
Older installed WASM/JNI clients do not enforce this extension and must be upgraded
before using these imported passkeys through standalone browser/Android providers.
The native gateway uses the updated native provider. This extension does not
change cryptographic wire formats or CXF's zero signature counter policy.

Bitwarden zero-counter discoverable passkeys with structurally valid PKCS#8 keys
map to passkey credentials. Other passkeys and OTP variants remain source metadata
with warnings. Cards, identities and SSH items are retained as opaque credentials.
Explicit Bitwarden URI match policies are preserved but omitted from active CXF
scope, to avoid silently broadening matching. Reprompt requirements are reported;
the importer does not implement authentication prompts. KeePass field references
remain literal and produce warnings; plugin-specific fields remain custom fields.

Original active item data, including history, are retained in vendor extensions
inside the encrypted payloads. These extensions are provenance, not authoritative
current values after subsequent editing. They can retain old passwords until an
explicit cleanup is implemented. KeePass active-entry attachment bytes are exposed
separately by `Conversion::attachments` / `into_parts`, keyed to the converted
source item ID; they are never embedded in CXF JSON. Native import encrypts those
files into owned attachment staging during preview and commits them with their
entries. Document-only consumers (`into_document`) discard separate bytes and
must retain attachment warnings. Bitwarden JSON provides references only; missing
file bytes remain an explicit omission. Custom icon blobs are not imported. Trash/recycle-bin items
are excluded, with warnings. This is not a lossless backup of the source database.
Keep source backups until the app can review these limitations. Empty collection
metadata remains available in the converted document and collection payloads.

KeePass uses pure Rust cryptography and decompression. Its upstream parser owns
decryption/KDF allocations and does not provide complete zeroization. The 32 MiB
encrypted input bound does not bound decompressed size, KDF memory or CPU cost;
run imports off the UI thread and do not treat the parser as a resource sandbox.
The converted document and encrypted-entry size limits still apply afterwards.
Do not log upstream database types, raw JSON, or typed CXF views.

Read-only Bitwarden inspection (counts and warning categories only):
`nix-shell --run 'cargo run -p kagitaba-cxf --example inspect_bitwarden -- /path/to/export.json'`.
Run importer checks with `cargo test --workspace --all-features` and
`cargo clippy --workspace --all-targets --all-features -- -D warnings`.

Source references for mappings:
- https://bitwarden.com/help/export-your-data/
- https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-exporters/src/json.rs
- https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-exporters/src/cxf/login.rs
- https://docs.rs/keepass/0.15.0/keepass/

## Firefox CSV import

`kagitaba_cxf::firefox::from_bytes` / `from_reader` convert Firefox password CSV
exports into the same reviewed CXF import pipeline. Native Import offers
**Firefox CSV**. Columns are matched by header name; `url`, `username`, and
`password` are required. Reordered columns, UTF-8 BOM, quoted multiline fields,
escaped quotes and CRLF are supported. Duplicate headers, invalid UTF-8,
malformed quoting and inconsistent row widths fail without including input values
in errors. The existing 32 MiB exchange input limit applies.

Each row becomes a basic-auth item; even duplicate source GUIDs/rows remain
separate until an explicit deduplication workflow. All source columns are preserved
in an encrypted Firefox source extension. Millisecond creation/password-change
timestamps map to CXF seconds; original values and last-used time remain in source
data. HTTP realms and foreign form-action origins remain inactive with URI-policy
warnings; ordinary origin matching must not silently broaden those restrictions.

Reference: [Mozilla LoginExport.sys.mjs](https://github.com/mozilla-firefox/firefox/blob/main/toolkit/components/passwordmgr/LoginExport.sys.mjs).
Synthetic tests cover CSV syntax, mapping, provenance and encrypted import.

## Version 1 wire formats

All fields below are concatenated bytes, no padding or delimiters beyond the
specified lengths. Magic includes the version and fixes the suite. Unknown magic
is rejected. These are Kagitaba formats, neither age nor HPKE. No format stability
or independent cryptographic review is promised for this initial prototype.

### Crypto ciphertext (`Ciphertext`)

`KTC1 || nonce[24] || SHA256(context)[32] || ciphertext_and_tag`

32-byte content key; XChaCha20-Poly1305. The whole 60-byte header is AEAD associated
data. Nonce is freshly random. Plaintext may be empty and is limited to 1 MiB.
Tag is 16 bytes. Context is non-secret, bounded to 64 KiB and supplied independently
on decryption. It is represented by its hash on the wire. Reject context mismatch.
Truncation/appending/corruption must fail authentication even when structurally valid.

### Crypto key envelope (`WrappedKey`)

`KTW1 || recipient_id[32] || SHA256(context)[32] || ephemeral_point[65] || nonce[24] || wrapped_key_and_tag[48]`

Exactly 205 bytes. The first 157 bytes are the authenticated header. The ephemeral
point is uncompressed SEC1 P-256 (`04 || x || y`); parsing validates the point and
rejects invalid points before invoking any hardware backend. Generate a fresh
ephemeral scalar and nonce for every wrapping operation.

```
Z = P256-ECDH(ephemeral_private, recipient_public)  # raw 32-byte x coordinate
salt = SHA256("Kagitaba/v1/ecdh-salt\0" || ephemeral_point || recipient_point)
info = "Kagitaba/v1/wrapping-key\0" || header
wrapping_key = HKDF-SHA256(ikm=Z, salt=salt, info=info, length=32)
wrapped_key_and_tag = XChaCha20Poly1305(wrapping_key, nonce, content_key, aad=header)
```

Both points in the salt are uncompressed 65-byte SEC1. Key and context mismatches
are rejected before prompting the backend. This is unauthenticated-sender public
key encryption; anyone with the recipient public key can create a new envelope.
Payload authentication is not a substitute for the app's trusted snapshot/signatures.

`KeyAgreement` is the hardware boundary: supply the raw 32-byte ECDH result, without
a hardware-specific KDF. PIN, touch policy, connection management and mapping a
fingerprint to a device/slot belong to the adapter. The private key never needs to
leave the device. The shared secret, wrapping key, content key and plaintext do
enter host memory. No on-device payload decryption is implemented. The USB/PIV
adapter implements hardware integration, but physical-key validation is pending.
`SoftwareIdentity` and a simulated PIV card exercise the same contract.

### Middle-layer primary (`PrimaryRecord`)

`KTP1 || entry_id[16] || revision_id[16] || opaque_body`

Body is at most 2 MiB. No assumptions about its format. Its digest is SHA-256 of
the complete canonical record including IDs. `content_context(id, revision)` is
`"Kagitaba/v1/content\0" || entry_id || revision_id`, available before encrypting.

### Middle-layer grant (`GrantRecord`)

`KTG1 || entry_id[16] || revision_id[16] || recipient_id[32] || primary_digest[32] || opaque_body`

Body is at most 64 KiB. `grant_context(recipient)` is
`"Kagitaba/v1/grant\0" || entry_id || revision_id || recipient_id || primary_digest`.
For the crypto backend above, the app uses that context for wrapping/unwrapping
and stores the `WrappedKey` bytes as the grant body. The middle-layer associations
can be forged without keys; inner AEAD verification and app trust remain required.

Secret owners have no `Debug`/`Clone`; content keys, raw ECDH output, intermediate
buffers and returned plaintext use zeroizing storage. RustCrypto secret scalar
types and the enabled AEAD zeroize feature clear their owned secrets. This is
best-effort memory hygiene, not protection against a compromised running process,
all compiler/register copies, or caller-created plaintext copies.

## Development and checks

Firefox also offers a connected native gateway mode, without browser participant
enrollment. Password and WebAuthn requests pass through an opaque Native Messaging
bridge and a private Unix
socket to the Linux client's explicit approval UI. See the native and extension
AGENTS.md files for protocol, installation, scope and validation.

Standalone Firefox extension design and implementation acceptance criteria:
`FIREFOX-DESIGN.md`. Each installation is a separate software participant,
unlocked through a physical key's WebAuthn PRF and operating on its own encrypted
replica. Keep implementation status and browser-specific operating instructions
with the extension; the design document is not evidence of completed validation.

Use the project `shell.nix` (`.envrc` contains `use nix`). System Rust executables
are rustup shims without a configured default. Use cargo to change dependencies.
The current Nix Rust package also ships `wasm32-unknown-unknown` standard libraries.
The development profile uses optimization level 1, retaining debug information
and assertions while avoiding unoptimized bulk crypto/JSON costs.

Full-history verification reuses already validated, unchanged entry subtrees
within a single traversal, keyed by entry ID and Git tree ID. Its reuse map is
limited to the previous snapshot; every commit signature, signer authorization,
snapshot membership, merge result and transition is still checked. Reused trees
still consume snapshot file/byte budgets. Nothing persists as a trust shortcut.
Immutable primary records retain their canonical digest in memory; wire formats
are unchanged. Cloned immutable primary/grant records share their opaque owned
body bytes; there is no mutable body accessor. Core batch entry replacement/removal APIs preserve validation and
copy a snapshot once for bulk edits.

```
nix-shell --run 'cargo test'
nix-shell --run 'cargo clippy --all-targets -- -D warnings'
nix-shell --run 'cargo check -p kagitaba-core -p kagitaba-cxf --target wasm32-unknown-unknown --lib'
nix-shell --run 'cargo fmt --check'
```

The workspace default member is `kagitaba-app`, so plain `cargo run`, `cargo build`
and `cargo test` target the Linux app. For whole-workspace
checks use `cargo test --workspace --all-features` and
`cargo clippy --workspace --all-targets --all-features -- -D warnings`.
The WASM check is `cargo check -p kagitaba-core -p kagitaba-cxf --target wasm32-unknown-unknown --lib`;
the native GUI, USB and Git storage crates are not WASM targets.
A read-only file inspector prints counts, never credential values:
`nix-shell --run 'cargo run -p kagitaba-cxf --example inspect_cxf -- /path/to/export.json'`.
The example reads plaintext CXF only and does not persist an encrypted import.

`tests/workflow.rs` is application-side composition of the two independent layers.
It demonstrates three participants, detached-grant enrolment, revisions/revocation,
opaque metadata and immutable snapshots. `tests/crypto.rs` tests byte-level
tampering, wrong context/key, hardware denial, parser checks and RNG failure.
`tests/reference.rs` uses independent PyCA/OpenSSL + libsodium vectors generated
by `uv run tests/reference_vectors.py`. Those C libraries are only external
reference tools; they are not linked into Kagitaba. Running ordinary Rust tests
does not require Python, hardware, network access or a random device.

Native architecture, UI patterns, operating instructions and limitations:
`crates/kagitaba-app/AGENTS.md`. `_Tasks/` is ignored local working material;
keep durable decisions and remaining work in the relevant `AGENTS.md` instead.

Use synthetic fixtures for development. Do not inspect real credential exports
unless their data is needed for an explicitly authorized import. Import tests
generate their own KeePass databases; independent exporter interoperability still
needs validation. Plaintext CXF support does not implement encrypted CXP transport.

Preserve the review regression coverage: entry-specific egui undo state, idle
locking during pending work, acceptance of non-secret wallet updates while locked,
deletion of inaccessible entries, full encrypted-envelope nesting limits (including
import provenance), and distinct empty versus absent KeePass passwords.

## Build SBOM and GitHub-attested Linux artifacts

`tools/build_release.py` builds the normal (non-smoke) Linux x86-64 application
with the locked dependencies and captures Cargo's actual per-artifact SBOM
precursor. It converts that graph to SPDX 2.3 JSON, retaining separate build units
and their features, normal dependency edges and build-script/proc-macro edges.
Only packages reachable from this executable's precursor are included; the
workspace-wide `cargo metadata` graph is used only for package/license enrichment.
Registry source-archive SHA-256 values come from Cargo.lock. The application
package checksum identifies the exact executable. Missing declared licenses
(including the currently unlicensed workspace crates) are explicit NOASSERTION
and flagged in `licenses.json`; no project license is assumed or assigned.

Local generation (requires uv and Python 3.11+):

```sh
nix-shell --run 'uv run --no-project --python 3.12 tools/build_release.py'
uvx --from spdx-tools==0.8.5 pyspdxtools -i target/dist/sbom.spdx.json
uv run --no-project --python 3.12 -m unittest discover -s tools -p 'test_*.py'
```

Output is `target/dist/`: executable, `sbom.spdx.json`, original `cargo-sbom.json`,
`licenses.json`, `build-info.json`, `SHA256SUMS`, and a tar.gz containing those files.
An existing nonempty output directory is refused; use `--output target/dist-next`
for another build. Compilation uses `target/sbom-build` so a cached ordinary
build without precursor capture cannot be mistaken for an SBOM build.
Local builds record the source commit and dirty status and
remain unsigned. Their Nix-linked executables require that local Nix environment;
the distributable Ubuntu build is produced on the GitHub runner.

This follows asteroid-watch's Cargo precursor approach: `RUSTC_BOOTSTRAP=1` and
`CARGO_BUILD_SBOM=true` are scoped to the packaging build invocation to enable
Cargo's still-unstable `-Z sbom` on stable Rust. Normal development/checks do not
set them. CI pins Rust 1.95.0, uv, and action commit hashes. Precursor schema or
target changes fail closed and require reviewing the converter. The SBOM covers
Cargo compilation inputs, not a whole OS image: Rust sysroot internals, graphics/
USB drivers, dynamically loaded OS libraries and non-Cargo build-script inputs
are outside its inventory. Declared licenses are not a notice/compliance audit.

GitHub Actions is the primary SBOM producer: every distributable app build must
capture and validate its SBOM; there is no skip switch or unsigned-release fallback.
`.github/workflows/check.yml` checks PRs without signing permissions, builds with
the same mandatory SBOM capture and validation, and uploads an explicitly unsigned
PR inventory for review (30-day retention). SBOM capture remains optional for
ordinary local development.
`.github/workflows/release.yml` checks and builds on main pushes or manual main
dispatch, then signs build-provenance and SPDX attestations using GitHub OIDC/
Sigstore, as in Secure-PWA. Both binary and archive are SBOM subjects. All initial
distribution files receive provenance attestations. Bundles are preserved beside
the artifacts and verified before upload. Outputs are Actions artifacts retained
for 90 days, not automatically published GitHub Releases. Download and retain
the artifacts and bundles for long-term archival.

Verify a downloaded artifact directory using this script from a reviewed source
checkout, with the source commit obtained independently from the reviewed build:

```sh
bash tools/verify-release.sh /path/to/downloaded-artifacts EXPECTED_40_HEX_COMMIT
```

After verification, extract the tar.gz to obtain the executable with its packaged
Unix permissions. The loose files beside it are also retained for inspection.

Verification pins `0x53A/kagitaba`, the main-branch release workflow's certificate
identity, source ref, source commit, and GitHub-hosted runners. It checks build
provenance, the SBOM attestation, and file hashes before any executable is run.
It requires a GitHub CLI with artifact-attestation support and access to Sigstore
trust roots. No GitHub signing identity can be generated or tested locally.
Attestations establish provenance, not source safety, reproducibility or release
freshness. The repository must support GitHub artifact attestations (public repos,
or private/internal repos with the applicable Enterprise Cloud capability).

References: [Cargo precursor schema](https://doc.rust-lang.org/cargo/reference/unstable.html#sbom),
[GitHub attest action](https://github.com/actions/attest),
[GitHub verification policy flags](https://cli.github.com/manual/gh_attestation_verify).

## Credential field and generator review

`FIELD-AND-GENERATOR-DESIGN.md` records the cross-client storage-constraint review,
implemented fixes, shared configurable password generator, TOTP camera/picture
import and bundled readable text-field font. It records platform acquisition
boundaries and remaining physical-device validation. Keep ordinary credential storage separate from autofill, passkey
and remote-transport eligibility checks.

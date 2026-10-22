# Immutable owned attachments, version 1

An item owns zero or more files; a file has exactly one owning item. There are no
shared file references, cross-entry deduplication, external fetches or filesystem
paths in attachment descriptors. File bytes are immutable: replacement is an
explicit remove/add operation. Rekeying changes encryption, not plaintext.

Each attachment is one encrypted repository file at
`entries/<owner-entry-id>/attachments/<blob-id>`. Owner and blob IDs are canonical
lowercase hex encodings of 16 bytes. Display filenames stay in encrypted item
metadata and never determine repository paths. Metadata and all attachment bytes
must be published in the same signed transaction. Entry-level merge atomicity
includes the complete attachment set; competing edits conflict as an entry unit.

## Encrypted item descriptor

Each owned attachment is a standard CXF `file` credential with an additive
application-specific `kagitabaFile` member:

```json
{"type":"file","id":"base64url-16-byte-attachment-id","name":"document.pdf",
 "decryptedSize":123,"integrityHash":"base64url-32-byte-SHA256",
 "kagitabaFile":{"version":1,"blobId":"32-lowercase-hex-digits",
 "key":"base64url-32-byte-key","chunkCount":1}}
```

The entire credential, including its key/name/hash, is encrypted inside its owning
item. Base64url is canonical and unpadded. Attachment IDs and blob IDs must be
unique within the item. An owned ID cannot alias an external file descriptor.
Only explicit `kagitabaFile` credentials activate local file access; ordinary
imported CXF file descriptors remain inert external references. Plain CXF import
planning explicitly rejects any `kagitabaFile` marker: JSON has no transport for
the corresponding owner-bound blobs, and remapping item IDs cannot transfer that
ownership. The original Document remains unchanged and serializable; use signed
wallet backups to transfer owned files. Markers are never silently stripped.

Keys are independently random 32-byte content keys. A fresh random blob ID is
allocated at creation and every rekey. The stable attachment ID survives rekeying.
Unknown descriptor members survive ordinary edits and rekeying. Advanced raw
editing cannot add/remove/change owned descriptors; dedicated attachment actions
are responsible for atomically updating descriptors and ciphertext.

A filename is a display/save hint only: 1–255 Unicode scalar values, at most 1024
UTF-8 bytes, no surrounding whitespace, controls, slash/backslash, `.`/`..`, bidi
override or isolate controls. A save action must still choose an explicit target;
it must never interpret the name as a trusted path or launch it automatically.

## One-file ciphertext container

`KAF1 || count[u32BE] || (length[u32BE] || chunk[length]) * count`

Count is 1 through 64. Every chunk is the existing core `KTC1` Ciphertext wire
format, using a fresh random XChaCha20-Poly1305 nonce. There are no trailing bytes.
Each non-last chunk encrypts exactly 1 MiB. The final chunk encrypts 1 byte through
1 MiB, except an empty file uses exactly one authenticated empty chunk. Ciphertext
length is plaintext length plus 76 bytes. Maximum file plaintext is 64 MiB;
maximum container length is 67,113,992 bytes. At most 128 owned files are allowed
per item, subject to the application's aggregate snapshot/transport limits.

Every chunk uses the same attachment key but independent random nonces. Its
caller-supplied context is the exact concatenation:

`"Kagitaba/attachment/v1\0" || owner[16] || attachment-id[16] || blob-id[16] || ordinal[u32BE] || count[u32BE] || total-plaintext-size[u64BE]`

Ordinal is zero-based. The existing KTC1 format authenticates SHA-256(context) in
its header. Owner binding prevents copying a descriptor/blob into another item
from giving that item usable access. Position, count, revision and size binding
rejects reordered, truncated, substituted and cross-file chunks. Authenticate all
chunks and verify the final size and complete plaintext SHA-256 before publishing
an export. A streaming decoder may write earlier chunks to private staging, which
must be discarded if final verification fails. Structural container parsing alone
is not authentication.

## Access and lifecycle

Ordinary metadata updates and additive sharing preserve attachment bytes. Access
reductions rotate every retained attachment key and blob ID, including ordinary
recipient-list edits and participant revocation. Re-encrypt all chunks, replace
the descriptors and blob files together, then sign the complete updated entry.
Rotating only the item key leaves retained attachment keys usable and is not the
required revocation operation. Historical recipients retain their historical
plaintext/ciphertext access, as with other credentials.

Deleting an attachment deletes its descriptor and blob together. Deleting its
owner deletes the owner's entire attachment set. Reader support, signed-history
transition validation and merge verification must cover the new paths on every
client before writers introduce attachments. A blob-tree change requires an
owner primary revision change, and a retained blob ID must retain identical
ciphertext bytes; normal changes to unrelated entry metadata may
leave the blob tree unchanged. The core crypto/wallet layers remain unchanged.

The shared `kagitaba-cxf::attachments` API performs no filesystem, Git, network or
hardware operations. Caller-provided randomness is required. Keys, returned
plaintext and retained descriptor names use zeroizing owners; this remains
best-effort memory hygiene rather than erasure of all temporary copies. Public
limits are operational bounds, not a claim that an arbitrary file fits every
existing repository/history transport budget.

## Streaming API and staging contract

`add_stream` reads a caller-specified exact plaintext size and requires EOF after
those bytes. It hashes and encrypts one chunk at a time into a caller-owned KAF1
staging sink. The finalized payload descriptor is returned only after successful
source length and EOF checks. `rekey_stream` authenticates/decrypts and re-encrypts
one file chunk at a time, returning its updated payload only after full input
validation. Call it for every retained attachment when reducing access; do not
publish any staged file or updated entry until all operations succeed.

`decrypt_stream` authenticates each chunk before writing it to private staging.
However, the complete plaintext SHA-256 and source EOF are checked only after the
last chunk. A late failure can therefore leave complete or partial plaintext in
staging. The caller must discard staging on every error and publish only after
success. This API must not be given a public/final export destination as its writer. Callers own cancellation, cleanup, private permissions, fsync and atomic
publication; shared helpers do not flush, sync, close or publish streams.

These helpers use O(chunk) temporary memory and no file paths. Existing buffered
helpers remain available for bounded tests/browser integrations. Public limits
remain unchanged. `expected_blob_size` validates descriptor size/count and gives
the exact KAF1 encoded length without reading data. `validate_blob_stream` checks
container structure and EOF with a 64 KiB scratch buffer; it does not authenticate
ciphertext or replace signed-history verification.

## Client availability

The current source implements native attachment authoring and compatible reader
paths/mutation safeguards for Firefox and Android. This does not upgrade installed
clients. The previously signed Firefox 0.1.2 XPI predates these attachment changes;
its version string must not be used as evidence of attachment support. Fresh
artifact builds and interoperability checks are separate from source/unit-test
validation. Upgrade and validate every client that will access an attachment-bearing
wallet before distributing that wallet.

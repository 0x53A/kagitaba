# Participant catalogue index v3

The index is an application cache, implemented in `kagitaba-store::index`. Entries,
recipient grants, participant enrolment and signed Git history remain authoritative.
The index never authorizes credential use. A credential is decrypted and validated
again when opened or used. The native client can reuse listing hints without a PIV
operation for every title on every search.

## Storage and lifecycle

- `participants/<participant-id>/index-key`: a normal 205-byte `KTW1` wrapper for
  a fresh random 32-byte index key, addressed only to that participant. Its context
  is the bytes `Kagitaba/index-key/v1\0` followed by the raw 32-byte participant ID.
- `cache/<participant-id>/index`: deterministic authenticated ciphertext, at most
  2 MiB including its header and authentication tag.

The key wrapper is authoritative participant metadata. Provision it before
independent rebuilds, retain it when invalidating the cache, and remove both the
wrapper and cache when removing a participant. Normal signed commits carry both
files. Independently provisioned wrappers conflict under the ordinary participant
merge rules; the application must not silently replace them.

Readers accept bounded opaque cache bytes, even malformed ciphertext, so a corrupt
cache cannot make an otherwise valid signed wallet unreadable. A cache requires an
enrolled participant and its key wrapper. Decrypt/parse failure is a cache miss.
Refresh failure should not prevent a requested authoritative wallet update: omit
that participant's disposable index and retain the wrapped key. A complete index
that cannot fit the limits requires the client's ordinary listing fallback.
Android uses shared transient index extraction for this fallback, preserving all
summary rows and collection links without persisting an oversized/partial cache
or a newly generated key wrapper. `Index::refresh` and `Index::seal` continue to
enforce the persisted format limits; `refresh_for_listing` is for transient use.

Each participant's entire `cache/<id>/` tree is a separate three-way merge unit.
Preserve identical and one-sided changes. Different concurrent changes, including
edit/delete, omit that cache tree. Remove caches of participants absent from the
merged authoritative snapshot. Received merge commits must match exactly the
same result. Cache conflicts do not resolve or relax authoritative conflicts.

## Ciphertext

`KTI3 || participant[32] || SIV-tag[16] || encrypted-plaintext`

Use RFC 5297 AES-128-SIV with the random 32-byte index key directly. The SIV primitive
uses two AES-128 keys; its key size is 256 bits and its security level matches the
P-256 recipient key. Supply exactly one associated-data component: the complete
36-byte `KTI3 || participant` header. There is no nonce, clock or Git commit ID.
Identical keys, headers and canonical plaintext deliberately yield identical bytes.
The suite and schema are fixed by `KTI3`; reject unknown magic.

## Canonical plaintext

All integers are unsigned big endian. A string is its UTF-8 byte length as a u32,
then those bytes. A string array is a u32 count followed by strings, strictly sorted
by UTF-8 byte order, with no duplicates. Strings are at most 16 KiB; arrays contain
at most 1024 values. The plaintext is:

1. Relevant-snapshot fingerprint, 32 bytes.
2. Row count, u32, at most 50,000.
3. Rows in strictly increasing raw entry-ID order. Each row contains:
   - Entry ID, 16 bytes.
   - Primary digest, 32 bytes.
   - SHA-256 of this participant's entire canonical grant record, 32 bytes.
   - Kind byte: 0 for item, 1 for root collection.
   - Password, TOTP and passkey presence, three bytes, each exactly 0 or 1.
   - Title string, usernames array, scopes array.
   - Collection-tree presence byte, exactly 0 for items and 1 for collections.
   - For collections, the recursively encoded tree described below.

A tree node contains: decoded CXF ID length u32 followed by raw ID bytes; title
string; direct local entry-link count u32 followed by 16-byte entry IDs in strictly
increasing order; unresolved-link count u32; child count u32 followed by child nodes in source array order.
IDs are nonempty and at most 1024 bytes. The root ID must equal the owning entry ID;
embedded IDs are opaque and need not be 16 bytes. IDs must be unique across each
tree. Each tree has at most 1024 nodes, 32 levels (root is level 1), and 50,000
links (local plus unresolved) in total. Node titles retain the 16 KiB string bound. The overall 2 MiB
ciphertext bound still applies, checked before allocating encoded output.

Collection extraction reads `title`, `id`, `items` and embedded `subCollections`.
Local membership includes only unqualified links whose decoded `item` is exactly
16 bytes. Links containing `account` are external and are never resolved against
wallet-local IDs. Account-qualified and non-16-byte target links increment the
unresolved-link count without retaining their external identifiers. Local links are sorted and deduplicated per node; missing or
inaccessible IDs remain in the index. Child order follows the source array.
Selecting a node filters the participant's already indexed entries against that
node's direct members; it does not grant access or decrypt a linked entry.
Collection names and retained decoded node IDs are wiped on drop.

KTI1 and KTI2 caches are cache misses and rebuild after unlock. The participant's
wrapped index key and relevant-snapshot fingerprint format are unchanged.

Trailing bytes, invalid UTF-8, noncanonical ordering, duplicate rows, unknown kinds
and invalid booleans fail parsing. Plaintext and retained row strings are cleared
on drop where owned; this is best-effort memory hygiene.

## Extraction and validity

Only accessible credential/collection entries are indexed. Participant metadata
entries are excluded. Title is the entity's string `title`, otherwise `Untitled`.
For `basic-auth`, collect `username.value` (or a string username) and mark password
presence only when `password.value` is a nonempty string. For `passkey`, collect string `username` and
string `rpId`, marking passkey presence. Mark TOTP presence for `totp`. Collect
string `scope.urls` and each `scope.androidApps` member as `android:` followed by
compact JSON with object keys explicitly sorted lexicographically at every depth
(independent of JSON map insertion order), preserving array order and exact
arbitrary-precision number tokens. Strings use UTF-8 JSON escaping: quote and
backslash are escaped, control characters use their short escape where available
and otherwise lowercase `\u00xx`; other Unicode characters remain UTF-8. Sort and deduplicate each
array. Do not index provenance, secret passwords, TOTP seeds or private keys.
Presence of a retained credential kind is not a claim that it is usable.

The fingerprint is SHA-256 over:

`Kagitaba/index-snapshot/v1\0 || participant[32] || relevant-entry-tuples`

Each tuple is `entry-id[16] || primary-digest[32] || SHA256(own-grant-record)[32]`,
sorted by entry ID. All parts have fixed lengths. Compute it from the verified
snapshot, never the working tree. Unrelated commits, cache commits and changes to
other recipients' grants do not invalidate this participant's index.

Refresh reuses rows only when both primary digest and own-grant digest match.
New access, changed primary or changed own grant triggers decryption; removal or
loss of the participant's grant drops rows without decrypting. Thus refreshing an
unchanged catalogue requires no entry private-key operations. Opening a persisted
index requires only the single index-key unwrap before decrypting the catalogue.

Version 2 requires a nonempty basic-auth password field value for password presence.
Version 1 caches are treated as cache misses and rebuilt after unlock; wrapped index keys are retained.

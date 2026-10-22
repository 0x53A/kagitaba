# Copying and exact duplicates

## Native workflows

**Tools → Delete duplicates…** scans readable items, shows survivor IDs and copies
to remove, then requires **Delete N duplicates and sign**. The lowest entry ID in
each equal group survives. All recipients are combined by generating missing
grants against that survivor's unchanged primary when no new provenance is needed.
When source metadata is combined, the survivor receives a new encrypted revision
with the union of recipients. Attachment bytes remain unchanged. Readable collection and item-reference links are redirected;
account-qualified external links are untouched. Unavailable entries are counted in
one warning line and are never deleted or modified. Dangling references remain
valid. Related-item merging is not implemented.

Every import offers **Skip N existing duplicates**, checked initially. Skipped
items become references to existing survivors in the new import collection.
While skipping is enabled, matched entry rows and their entry-specific diagnostics
are hidden from review; unchecking restores them. Collections remain visible.
Selected import recipients receive missing grants to those survivors. The new
collection hierarchy is retained even when every item already exists.

**Tools → Copy to wallet…** selects readable credential entries and a destination
folder. The destination must have been opened and explicitly trusted previously.
The source stays unchanged. Copies get fresh entry IDs and fresh attachment
ciphertext bound to their destination owners. Local references among selected
items are remapped together; unselected targets become explicitly unresolved,
account-qualified references rather than accidentally resolving in another wallet.
Collections themselves are not selected by this item-copy workflow.

The current key can authorize the copy only if its encryption and signing keys
are both enrolled in the destination. Otherwise the copy screen requests a
separate destination key and PIV PIN. Source hardware is released before opening
the destination key; destination authorization is never published as a source
wallet unlock. Recipient selection and signing follow destination unlock and
verification. The destination signing key signs the destination commit. A separate
physical-key switch still requires manual end-to-end hardware validation.

Copy and import reviews offer the same duplicate policy. Selected destination
recipients are explicit; source grants are not copied to a different wallet.

## Equality and transaction boundaries

Comparison uses current item content across exporters: title, usernames, passwords,
notes, URLs/scopes, TOTP/passkey data, custom fields and authenticated owned files.
Unknown active fields, unknown credentials and unknown extensions remain meaningful.
New item IDs and owned attachment IDs/blob IDs/encryption keys are ignored.
Known credential/field order and URL/app-scope order are presentation differences;
unknown credential positions remain meaningful. Narrow empty defaults and absent versus false favorites normalize,
but absent and empty passwords remain distinct.

Import `source`, the known KeePass/Bitwarden/Firefox source extensions, and item
creation/modification timestamps do not prevent matching. These are preserved,
including history and unknown source data, in the survivor's original metadata and
a versioned encrypted `kagitabaImportProvenance` envelope member. Its format is
`{version:1,records:[{source?,extensions?,creationAt?,modifiedAt?}]}`. Records are
canonically deduplicated; original active content stays unchanged. Reimporting an
already retained source neither grows the archive nor creates a new revision.
Unsupported archive versions/shapes fail closed; exceeding the entry size limit
fails the transaction instead of discarding metadata. Importer-generated KeePass
`protectedFields` is a set and is normalized for legacy random map order.

Every owned file is authenticated through bounded streaming before its content
hash participates in equality. File names, bytes and unknown file metadata must
match. Transient digests are never persisted as a password index or logged.
Collections remain organizational payloads and are not themselves deduplicated.
Freshly remapped item-reference identities can still keep related items separate;
this is not a heuristic title/username/password-only merge.

The preview provides advisory counts for unmatched same-source records using
static current-content categories, never field values or secret IDs. These
explanations do not authorize skipping or weaken matching.

Reviews bind the accepted snapshot head and participant. Grant/signing failures
return no partial candidate, and concurrent destination updates fail the store's
normal compare-and-swap check. One signed update publishes all entry/grant/link
changes. Lock, navigation and wallet replacement clear pending plaintext and
private encrypted staging. Hardware denial stops scans instead of retrying each
entry. A signed write already completed before a queued lock is not rolled back.

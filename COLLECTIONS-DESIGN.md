# Collection navigation

## Interaction

The wallet browser offers these filters in order:

1. **All entries** (initial selection).
2. **Entries not in a collection**.
3. A tree of readable root collections and their nested collections.

All entries lists credential items, including items outside collections. Collection
records are shown in the tree rather than mixed into the item list. Selecting a
collection shows its direct members; nested collections are separate tree nodes.
The unfiled filter excludes items linked by any readable node, including descendants.
It cannot account for membership in collections the current participant cannot read.

Wide layouts place collection navigation left of entries. Compact layouts keep
the same filter order in a space-appropriate control. Entry rows emphasize title
and username; abbreviated IDs are smaller, muted secondary information. Details
remain an explicit selection, with existing reveal/decrypt controls preserved.

## Data and access

The native participant index caches the collection hierarchy and membership along
with item summaries. Collection selection only filters these cached hints; it
performs no private-key operation. Firefox and Android use their existing readable
payload state. No client persists plaintext collection navigation preferences or
names. Lock and wallet replacement clear decrypted navigation state.

A collection link is organizational, never an access grant. Resolve only local,
unqualified item links by decoded identity. Account-qualified links remain external
or unresolved even if their item bytes happen to match a local entry. Missing or
inaccessible members do not disappear from the authoritative collection payload.
Browsing must not fetch external links or automatically decrypt target secrets.

Each root and its embedded subcollections remain one encrypted collection entry.
Navigation does not split roots, change grants, or rewrite membership. Collection
editing continues through the existing payload editor.

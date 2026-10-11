# Kagitaba

_yet another vibecoded password manager_

## Why?

I recently got a yubikey and was surprised to find how limited support for hardware-based encryption in mainstream password managers still is.

As a single key presents a potentially fatal single point of failure, a reasonable workflow requires at least three hardware keys: one on your keychain, one at home, and one stashed at a friend or family member.

## Key management

With one key stashed away, it needs to be possible to add new entries, decrypteable by this key, without the participation of the key.

It should also be possible to *enroll* a new key, using any existing key, without both keys needing to be physically present at the same time.

You're on vacation, and lose your primary key. Your second key is at home. What do you do?

With my envisioned scheme, you buy a new key in a local store (or get express delivery), call your friend, tell him the PIN of the key you stashed at his place and send him the public key of your new hardware key. He'll use that to enroll your new key in your wallet.

## Entry management


It should be possible to decide per-entry who can decrypt it.

Previously I focused on multiple hardware keys for a single user, but this can be trivially extended to support sharing specific credentials with friends and family (or coworkers).

Most local password managers encrypt the whole database using a master key, which can be a master password or material in a hardware key.


## Backend storage

Most password managers use either a shared remote database (Bitwarden/Vaultwarden, ...) or a local single-file database (KeePass, ...).

For me, relying on a thirdparty web backend is out, on principle. The single-file concept is nice, for one computer, but I need my passwords synchronized between four or more devices, and explicitly handle concurrent edits and conflict resolution.

Do you know what else handles concurrent edits and conflict resolution?

...

...

Git repositories.

Instead of compressing everything into one file, Kagitaba on purpose splits up functionality into individual files.

If you edit an entry, only the file(s) of that entry are modified. Concurrent edits to *independent* entries can be trivially merged using raw git. Concurrent edits to the same entry need the application to handle the merge, as both sides need to be decrypted to merge the logical edits, but that's still so much better than what happens typically with a single-file db synced using, say, Dropbox or iCloud, which is that the last edit wins, other edits are potentially lost.

## Comparisons to other managers

Bitwarden / Vaultwarden, LastPass all use a web backend with entries in a database like sqlite or postgre. DB breaks? Server is offline? you're fucked. (well, the database is cached locally, but copying entries between devices without the server is gonna be hard.)

KeePass has limited support for hardware keys. You can unlock one database with multiple keys by basically cloning them - enrolling the same `hmac` secret into all of them. This only protects the whole database, you can not control access to individual entries inside one database.
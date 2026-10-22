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
## Firefox through the native client

Firefox can use the Linux wallet without enrolling the extension as a separate
participant. Build the app and extension, then register the native host:

```sh
nix-shell --run 'cargo build -p kagitaba-app'
nix-shell --run 'uv run --no-project tools/build_firefox.py'
uv run --no-project tools/install_native_host.py "$PWD/target/debug/kagitaba-app"
```

For permanent installation in standard Firefox, use a Mozilla-signed XPI via
**Add-ons → gear menu → Install Add-on From File**. The local build above is
unsigned; signing is a separate unlisted AMO submission. The native host must
still be registered separately.

For temporary development installation, load `extension/firefox/dist/manifest.json` through Firefox's
`about:debugging#/runtime/this-firefox` (Load Temporary Add-on). Open and unlock
the native wallet. On an HTTPS login page, open Kagitaba from the Firefox toolbar,
select **Use native client**, then **Choose login in native client**. Select the
entry and approve the displayed origin in the native window. Its saved website
scope must match the page's exact HTTPS origin. The form is filled without submission.

The gateway uses a private Unix socket under `$XDG_RUNTIME_DIR/kagitaba`.
It supports password filling and ES256 passkey registration/sign-in. Website
passkey requests open the native approval window; find/select a matching account
for sign-in, then verify your PIV PIN. Registration saves the encrypted passkey
before reporting success. **Use standalone wallet** switches back to the independent
browser participant. See [native gateway details](crates/kagitaba-app/AGENTS.md#firefox-native-gateway)
for the protocol, security boundary and validation limits.

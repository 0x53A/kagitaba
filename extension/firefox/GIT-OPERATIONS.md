# Encrypted Git replicas

The extension keeps an independent encrypted Git object database in IndexedDB.
Only the accepted head and pinned root authorize data. Remote connection takes
URL, username and token/password and uses trust on first use: the genesis signer
is discovered from the fetched history, the complete chain is verified, and its
root/head are pinned locally. It cannot detect substitution or stale history on
that first connection. Manual transfer bootstrap retains independent root and
checkpoint input. Fetch writes
objects but does not advance that checkpoint until the entire linear history,
Rust SSHSIG verification, signer transitions, and snapshot records pass checks.
Local writes flush the object database and accepted checkpoint before succeeding.
Transport authentication can be remembered as an encrypted local credential. It is
bound to the exact normalized HTTPS remote URL and username, and encrypted through
Rust/WASM using an identity-derived, domain-separated key. Unlock is required to
reuse it. It never enters the repository, participant recovery package or backup.
Unchecking Remember removes the persisted ciphertext and retains the token only
for the unlocked session; locking clears that session copy. Automatic sync is an
explicit preference, runs after local writes and unlocking, and never merges or
retries conflicting history automatically. The last safe error/outcome and sync
timestamp persist for feedback. The Git transport itself is implemented by
the replica module. HTTPS smart Git is supported; SSH transport is not.

The browser Git library performs ordinary object plumbing, including its own
internal SHA-1. Every object used as trusted wallet input is independently hashed
by the Rust adapter; wallet encryption and signing remain Rust operations.

Native enrollment already exists in the desktop Keys workflow. Export the
extension participant request as `kagitaba-participant-1` JSON, import its public
keys in the desktop client, compare fingerprints, confirm enrollment, and grant
the participant access to the intended entries. Enrollment includes a separate
signing key; merely registering it does not grant entry decryption.

For offline bootstrap, export a complete encrypted history from an existing
wallet using the store example. Supply an independently trusted root signing PEM
and a known accepted commit hash:

```
nix-shell --run 'cargo run -p kagitaba-store --example browser_transfer -- export /path/to/wallet /path/to/root-signing.pem CHECKPOINT /path/to/transfer.json --confirmed-trust'
```

The output must not already exist. Import it in the extension and independently
confirm the root/checkpoint. The root contained in a transfer is only a hint and
is not automatically trusted. Transfer files contain public metadata and encrypted
entries. After browser enrollment, they also contain the encrypted participant
recovery envelope and public FIDO credential/PRF parameters under that participant's
`browser.json`. They never contain plaintext participant private keys. Recovering
that participant requires the original physical key and explicit recovery intent;
normal new installations generate a distinct participant.

For browser changes back to the native wallet, export the browser transfer and:

```
nix-shell --run 'cargo run -p kagitaba-store --example browser_transfer -- import /path/to/wallet /path/to/root-signing.pem CHECKPOINT /path/to/browser-transfer.json --confirmed-trust'
```

Import rejects divergent or rolled-back history and requires a clean native
wallet checkout. It accepts either the raw Git transfer or the extension backup's
outer `wallet` wrapper; unsigned outer installation metadata is ignored by native
import. Keep the newly printed checkpoint in the trusted record.
Alternatively synchronize both clients with the same HTTPS Git remote. Browser
sync only accepts fast-forwards or pushes its verified descendant, never merges
or force-pushes. A concurrent remote update may reject the push safely.

Tests use synthetic temporary repositories. Node transport tests use a deliberately
simple signing boundary double; the Rust store regression uses genuine P-256
SSHSIG signatures and rejects modified transfer objects and history rollback.
Live remote/provider behavior and physical-key unlock need separate validation.

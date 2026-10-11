# Standalone Firefox extension

This is the agreed direction for Kagitaba's browser client. It describes the
intended implementation, not a claim that the features or hardware combinations
have already been validated.

## Product and workflows

The Firefox extension is a complete wallet client and software passkey provider.
It runs without the desktop application, native messaging, or a local service.
It provides password matching and explicit autofill, password saving/updating,
and website passkey registration and authentication. Website passkey private keys
remain encrypted in the wallet between uses. Firefox's own authenticator handling
remains available for physical security keys and other providers.

Use the application's friendly blue/aqua visual language, with clean, functional
screens and clear tasks: enrol this installation, connect a wallet, unlock, select
a credential, approve a request, save an entry, synchronize, and lock. Show the
requesting website and account in extension-owned approval UI. Never ask the user
to approve a secret operation in UI controlled by the requesting page.

## Participants and physical keys

Each extension installation/browser profile creates its own software participant
key pair. Different computers, browsers, and profiles are distinct participants.
An existing authorized client registers its public key and grants it access to
explicitly selected entries. Registration alone grants no entry access. Signing
authorization is separate and must also be enrolled for a writing client.

The participant's private material is encrypted in extension storage. A physical
YubiKey unlocks it using WebAuthn PRF, a domain-separated key derivation, and
authenticated encryption. This is separate from the native application's PIV
participant: a FIDO credential does not expose the PIV ECDH or signing slots.
Once unlocked, the software participant and software website passkeys are usable
in browser memory. This does not provide hardware-bound private operations for
the participant or for website passkeys.

Default to one unlock credential per installation, using a non-discoverable FIDO2
credential where the browser/key supports PRF. Store its credential ID, RP ID,
PRF input, derivation/version parameters, and encrypted envelope. Non-discoverable
credentials avoid consuming YubiKey discoverable-passkey slots. Probe actual PRF
support and fail explicitly if it is unavailable; a successful ordinary WebAuthn
assertion alone is not a decryption key. Do not silently substitute weaker unlock.

One primary YubiKey is sufficient. Additional keys may each wrap the same random
unlock secret, so any enrolled key can unlock the installation. Existing native
PIV backup grants do not automatically become browser unlock credentials. A lost
installation can instead be replaced by enrolling a new participant using a
remaining authorized wallet participant. Recoverability requires preserving the
encrypted wallet and the appropriate enrolment/unlock information.

Choose a stable, explicit RP ID and extension identity, with only the permissions
needed for their use. Browser participants remain independent even if the same
physical key unlocks them. Sharing participant private keys between installations
is possible in principle but is not the default workflow.

Include the PRF-encrypted participant package and its public credential ID,
PRF input, RP ID, installation context and format version in the participant's
enrolment request. The authorizing client preserves that package as signed
`participants/<key-id>/browser.json` alongside the public keys. No plaintext
private key or PRF output belongs in the repository. This permits explicit recovery
of the same participant from the encrypted replica with the original physical
key. Fresh installations still create separate participants by default. Recovery
does not restore freshness by itself: trusted root/checkpoint decisions remain
outside the synchronized wallet and must be re-established independently.

## Storage, trust, and synchronization

The extension keeps its own encrypted replica in persistent extension storage,
such as IndexedDB. It does not directly open the desktop wallet directory or use
ordinary browser cache as durable storage. The native client and extension can
synchronize through a common Git remote. Manual encrypted transfer also provides
an offline bootstrap/backup route; it must preserve authenticated history and
trust information rather than importing an unauthenticated working tree.

Reuse the existing record formats, recipient grants, CXF envelopes, and signed
Git history policy. Implement browser-compatible storage and transport; do not
invoke a native Git executable. Remote authentication is independent of wallet
decryption. Explain supported transports and protect stored remote credentials.
Persist trusted checkpoints and verify committed bytes and authorized signers
before exposing a new snapshot. Remote connection uses trust on first use: the
user selects an HTTPS URL and credentials; the extension discovers the genesis
signer, verifies the fetched history and pins that root and accepted head locally.
This does not independently authenticate the initial history or prove its freshness.
Manual transfer bootstrap retains explicit root/checkpoint input. Reject rollback,
unsigned history, unauthorized signers,
and divergence; do not automatically merge, force-push, or discard local edits.

Writes create complete matching revisions and grants, with fresh content keys.
Keep local changes durable before reporting success, and distinguish saved locally
from synchronized. New passkey registration must durably retain the credential
before returning success to the website. Uninstall/profile loss may destroy the
local replica: offer encrypted backup and make pending synchronization visible.

## Browser security boundaries

An injected page bridge adapts navigator.credentials.create/get to the extension
and retains native fallback. The bridge and all page messages are untrusted.
The privileged extension validates the actual sender tab/frame/document, origin,
secure context, RP ID relationship, challenge, supported algorithms, credential
allow/exclude lists, and request lifecycle. Do not trust a page-supplied origin.
Handle navigation, cancellation, timeouts, lock, and concurrent requests without
cross-delivering a credential or approval. Reject unsupported cross-origin/frame
cases explicitly until their full WebAuthn policy checks are implemented.

Implement supported WebAuthn responses correctly, including clientDataJSON,
authenticator data, signatures, credential IDs, and user handles. User presence
and user verification are different: never assert UV merely because the user
clicked approve. Enforce requested verification with an actual verification flow,
or reject/fall back. Imported CXF passkeys require a zero signature counter.
Preserved unsupported credentials must never become active by accident.

Password matching uses explicit origin/scope rules and respects supported import
match policies. Require an explicit fill/save choice, isolate frame destinations,
and do not send the whole vault or passkey private keys to content scripts. Lock
on timeout and user request; invalidate pending secret operations and clear
decrypted caches. Keep secrets out of logs, errors, fixtures, and persisted indexes.

Reuse Rust core/CXF through bundled WASM and keep application policy outside the
opaque layers. Cryptographic implementation remains Rust; browser APIs supply
randomness and WebAuthn. Bundle all executable assets, with a restrictive CSP and
minimal permissions. JavaScript/WASM memory cleanup is best-effort, not a claim of
complete erasure or protection from a compromised browser.

## Delivery and validation

Deliver a buildable, locally installable Firefox extension with operational setup,
enrolment, unlock, wallet browsing/editing, autofill/save, software passkey
registration/authentication, encrypted persistence, and verified synchronization.
Include the necessary native-client enrolment/transfer integration so an existing
wallet can actually authorize and grant access to the installation. Do not stop
at a UI mockup, isolated signing demo, or scaffold with production-path stubs.

Use synthetic fixtures and meaningful browser/integration tests for origin/RP
confusion, forged messages, wrong-key/tampered envelopes, lock races, persistence,
signature/trust failures, sync conflicts, and passkey registration/assertion.
Preserve existing workspace regression tests and portable WASM compatibility.
Document exact build/load/test commands and supported browser/key versions.
Physical-key and real-site checks that cannot be run must remain clearly marked
as pending; passing simulated tests is not physical-device validation. Marketplace
publication, signing submissions, and Git commits/pushes are separate actions.

## References

- [WebAuthn specification](https://www.w3.org/TR/webauthn-3/)
- [WebAuthn in extensions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Use_the_web_authn_api)
- [Yubico PRF guide](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)
- [Discoverable and non-discoverable PRF support](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)
- [Bitwarden's extension provider architecture](https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension/)
- [Extension storage permissions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions#unlimited_storage)
- [CXF 1.0 with errata](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html)

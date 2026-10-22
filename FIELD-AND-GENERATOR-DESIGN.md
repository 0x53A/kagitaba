# Credential fields, generation and TOTP

Implemented across Linux, standalone Firefox and Android. Firefox native mode
uses the Linux editor and also offers the independent browser generator.

## Storage and use

Ordinary entry URLs are retained as supplied, including HTTP, SSH/custom schemes,
bare hostnames, empty strings, paths, queries and fragments. Editing a password
never canonicalizes the URLs. Each URL can be edited or explicitly removed.
Username/password and note editors support multiline Unicode text without trimming.
Multiple basic-auth credentials can be edited independently; missing password
fields can be populated by the generator. New logins and notes can be added.
Unknown credential members remain intact. Firefox applies form patches to the
original Rust-parsed JSON; advanced raw editing still takes precedence over forms.

Autofill origin/caller checks, passkey RP binding, remote transport eligibility,
PIN/key rules, signed history, authenticated IDs and resource bounds remain in
force. Storage does not authorize credential release. Unsupported typed values
are not automatically activated because they are preserved.

TOTP periods and digits are stored as positive u64 numbers, independently of
upstream's u8 typed model. Validation makes a disposable normalized typed view
without rewriting authoritative JSON or traversing vendor/provenance fields.
`Document::typed()` remains an upstream view and can fail for values that its
model cannot represent; use the preserved JSON for editing/export. Older client
builds may reject these wider values: update all replicas before using them.
Code generation supports SHA-1/256/512, 6–8 digits, and positive u64 periods.
Other stored values remain visible/editable with explicit generation errors.

Android no longer silently truncates local wallet names or counts UTF-16 units
against the participant-name scalar limit. Shared participant metadata validation
still owns the agreed name bounds/control-character policy.

## Password generator

Linux: header **Tools → Password generator**. Firefox: **Password generator** at
the top of the wallet window, also before enrollment and in native mode. Android:
header **Generate**. These tools require neither an unlocked wallet nor hardware.
Entry editors offer **Generate… → Use password**, which changes only the draft.
Explicit Save is still required. Cancel leaves the entry untouched. The password
at the website is never changed by these actions.

All clients call `kagitaba-cxf::password::Rules` directly or through WASM/JNI:

- Default length 12; lowercase and digits enabled, uppercase and symbols disabled.
- Lookalikes excluded: `iIlL1oO0sS5zZ2bB8gG6qQ9`.
- Default effective alphabet: `acdefhjkmnprtuvwxy347` (21 characters).
- At least one character from each selected class; repetition allowed.
- Length 1–1024, class toggles, editable punctuation alphabet, optional lookalike
  exclusion, additional exclusions and optional per-class requirement.

The 12-character readable default provides roughly 53 bits of choice before the
class-presence condition. Users can select longer output. Rules apply only to
newly generated values, never to manually stored passwords. Empty/impossible
alphabets and insufficient lengths fail explicitly. Changing controls invalidates
the old output. Copy, reveal and application are explicit actions; no generated
history or generated values are persisted as preferences.

Sampling uses integer completion counts and an unbiased random rank, then
unranks it into a valid string. This avoids modulo bias and the poor acceptance
rate of whole-password rejection for unusual class combinations. Linux uses
SysRng, Firefox crypto.getRandomValues and Android SecureRandom. Entropy failure
never falls back to deterministic output. The helper is application code, not
part of opaque core crypto. Big-integer internals and platform UI copies do not
guarantee zeroization; the existing best-effort memory-hygiene limits apply.

Generator/scan dialogs clear on lock, close and timeout. Clipboard copies use
ownership checking and a 30-second expiry attempt. Firefox/Android may deny later
clipboard reads; system clipboard histories remain outside this guarantee.

## TOTP camera and picture import

Each entry editor offers **Import TOTP (camera / picture / URI)**. Import a local
PNG/JPEG, scan a camera, or paste an `otpauth://totp/` URI. The shared Rust decoder
finds distinct supported codes. Multiple codes require selection. Review issuer,
account, algorithm, period and digits, then **Add to entry draft**; Save remains
explicit. No URI is fetched, no code is uploaded, and no photos are written to a
gallery or temporary file. HOTP, migration QR bundles, unknown URI parameters and
unsupported algorithms fail explicitly rather than being misinterpreted.

Acquisition is application-owned:

- Linux decodes local images in a worker. **Scan camera** uses a selected
  `/dev/videoN` through `ffmpeg` on PATH, with live preview, cancellation and a
  bounded scan. `shell.nix` supplies ffmpeg; packaged installations need it for
  camera capture. No shell interpolation or network input is used.
- Firefox requests getUserMedia permission only on Scan camera. A local video
  and canvas feed the WASM decoder. Tracks stop on completion, cancel, close,
  timeout and lock. Picture selection uses the same decoder.
- Android requests CAMERA permission on demand. Camera2 preview and YUV planes
  stay inside the app; no external camera intent is used. Picture import uses
  the system document picker. `QrPixels` handles bitmap and strided camera-plane
  conversion before JNI. Camera closes on backgrounding; the picture-picker
  callback can still complete if its original dialog remains live.

Images are bounded before/while decoding where the platform permits; decoder
input is at most 2048×2048 grayscale pixels. Original files remain untouched.
Camera scans stop after a bounded interval and can be retried. Cancellation/lock
invalidates pending results. Linux/Firefox refresh displayed TOTP codes; Android
shows them in a refreshing dialog. Unsupported stored parameters remain intact.

## Text readability

All editable fields use the bundled **DejaVu Sans Mono 2.37**, including titles,
usernames, passwords, URLs, search, names, PINs, remote credentials, JSON, notes
and generation/import controls. Revealed/read-only credential values use it too.
Native navigation labels retain their proportional UI font. Android reapplies
the field font after changing input type; Firefox disables ligatures in fields.
Unicode fallback and platform scaling remain available. Visual review confirms
distinct `i I l L 1 | o O 0`; zero has an interior dot.

Canonical font and license: `assets/fonts/`. Android packages a copy; Firefox's
build copies the canonical files; Linux embeds the font and its release archive
includes `FONT-LICENSE.txt`. Upstream source/license:
https://github.com/dejavu-fonts/dejavu-fonts/tree/version_2_37

## Validation boundaries

Synthetic coverage includes generator rules, entropy failure and parity vectors,
TOTP vectors/wide periods, opaque field preservation, QR pictures and rotated or
padded camera frames. Firefox's real-browser smoke exercises signed entry edits,
picture import and a synthetic canvas MediaStream through the actual scan loop.
Linux has a decoded-image test plus narrow/wide GUI regression checks. Android
has packaged-JNI instrumentation for pictures, camera planes and field edits.

Physical cameras, Android camera permission/device quirks and a physical PIV key
remain separate manual validation. Tests do not read real credentials or operate
on physical hardware. Current task execution results are recorded in the numbered
work folder; the existence of a test is not evidence it has been run successfully.

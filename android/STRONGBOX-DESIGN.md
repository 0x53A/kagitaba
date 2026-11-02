# Phone StrongBox participant

## Behavior

A phone participant owns two P-256 keys generated through AndroidKeyStore with
StrongBox explicitly required: ECDH for existing Kagitaba grants and ECDSA/SHA-256
for signed wallet history. Private scalars are never exported. The ECDH shared
secret enters application memory; Rust still owns HKDF, grant unwrapping, payload
encryption/decryption, index encoding and history verification. This is the same
cryptographic boundary as PIV, not the old AES-wrapped software identity.

Enrollment defaults to a 60-second authentication window. The creation dialog
accepts 1–300 seconds, fixed in both keys at generation. Keys require strong
biometric or device-credential authentication and an unlocked device. Generation
and enumeration verify StrongBox security level and hardware-enforced user
authentication. There is no TEE/software fallback. The phone backend requires
Android 15+ to avoid the documented Android 12–14 unlocked-device policy bugs;
it uses APIs supported by the user's Android 17 baseline without changing the
existing PIV application's minimum SDK.

Home → Create enrollment request → Choose phone or YubiKey → Phone creates or
selects an installation-owned key pair and exports the existing public participant
request format. Enroll this request with an existing wallet participant on the
computer, grant desired entries, and sync. Add existing continues to clone and
verify history before unlocking; phone selection compares both public keys with
the verified participants. Create new also supports phone keys. Provider/autofill
foreground authentication uses the same backend chooser.

Existing phone pairs are enumerated only in this app's namespace, using dedicated
UUID aliases. Invalid/incomplete pairs are not offered. New generation never
overwrites an existing alias; failed generation removes only that attempt's keys.
A completed pair survives cancellation of enrollment and is offered next time.
No private material or phone routing metadata goes into wallet Git. The same
installation key can be enrolled into multiple wallets. Changing its authentication
window requires a replacement pair and normal participant enrollment/revocation.

## Authentication and cancellation

An explicit BiometricPrompt starts each phone session, even when the hardware
window could already be valid due to device authentication. Private operations
run on the IO worker. UserNotAuthenticatedException triggers a foreground prompt
and retries that single private operation once. An index rebuild therefore keeps
its progress across window expiry. Cancellation or another error aborts the
operation; no whole write or batch is replayed. Authentication timeout is not an
application session timeout and does not erase content already decrypted.

Prompts use a worker latch released on success, denial or session close. App lock
invalidates Kotlin and native session state, cancels prompts and rejects late
results. Destroying the current phone-authentication activity normally locks that session.
A successful Credential Manager unlock response with credential choices is the
narrow exception: an epoch-bound marker permits detaching/canceling the prompt
host while retaining the session and issued selection tickets for the system
picker. Empty responses, cancellation, final credential responses and other
activity destruction still lock. Explicit lock, screen-off and idle expiry always
revoke the session and clear tickets, including during this handoff.
The native session map contains callback references and public keys only. No map
lock is held while calling Java or waiting for authentication. Closing a native
handle marks the backend inactive even for operations that already cloned it.
The platform's remaining timed authorization cannot be revoked by closing our
handle. Screen lock adds the independent unlocked-device requirement.

Normal in-place APK updates preserve Keystore keys. Uninstall, app-data removal,
reset or permanent key invalidation can lose this participant; another enrolled
YubiKey remains the recovery path. Neither exports nor backups recover the phone's
private key. The retained legacy DeviceIdentity is not migrated or activated.

## Validation boundary

PhoneInteropTest exercises a synthetic independent JCA callback through packaged
JNI: ECDH unwrap, signed storage, index cache reuse, callback errors, malformed
ECDH output, session close, and close during signing without publishing a commit.
PhoneEnrollmentTest checks the default window and failure without software fallback
on an emulator lacking StrongBox. PhoneAuthenticationTest uses a synthetic
emulator Keystore key with a two-second window: real device-credential prompts
authorize ECDH, expiry prompts again, and close cancels a pending prompt.
JVM session tests reject late authentication callbacks and private-work results.
These tests do not claim StrongBox backing. Actual StrongBox generation and
policy enforcement, physical biometrics and APK-update persistence still require
a physical-device check. Laptop
remote use is not implemented by this change.

References:
- https://developer.android.com/privacy-and-security/keystore
- https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder
- https://source.android.com/docs/security/features/keystore

ECDSA provider selection: use `Signature.getInstance("SHA256withECDSA")`,
then initialize with the Android Keystore private-key handle. Android registers
its signature implementation in a companion provider, not the `AndroidKeyStore`
provider used for key management and ECDH. Automatic JCA selection here does not
export the key or enable a software-key fallback. PhoneAuthenticationTest covers
this exact production signing callback with a Keystore handle and also tests
signing reauthentication after the authorization window expires.

2026-10-31 signing fix validation: the focused Keystore signing regression fails
with NoSuchAlgorithmException on the old APK and passes on the corrected APK.
The expanded signing-expiry UI test was blocked by emulator System UI/locked-device
faults in this run; its new signing branch is not yet validated. The corrected APK
was installed in place on the Pixel; user-driven StrongBox signing confirmation
is still needed.

Provider handoff regression: PhoneProviderHandoffTest supplies synthetic successful
phone authentication and keys through instrumentation-only reflection, then uses
real ProviderActivity lifecycles, framework requests/responses and PendingIntents
to exercise unlock -> candidate response -> authentication activity destruction
-> selection -> password result. It also checks explicit lock, idle expiry, screen-off and
abandoned authentication. The regression fails on the previous APK and passes
on the corrected APK in the disposable API-35 emulator. There is no production authentication bypass and this
test does not claim physical StrongBox or biometric validation.

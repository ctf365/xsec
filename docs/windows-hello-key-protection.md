# XSec Windows Hello key protection

This document describes the Windows implementation currently shipped by XSec.
`crates/xsec/SYSTEM_PROTECTOR.md` remains the format-level specification.

## Security model

XSec follows the persistent Windows Hello unlock design used by Bitwarden
Desktop:

1. Generate a random per-enrollment challenge.
2. Ask the Windows Hello `KeyCredential` to sign that challenge.
3. Hash the deterministic signature with SHA-256 and derive a KEK with
   HKDF-SHA-256.
4. Wrap the XSec DEK with AES-256-GCM under that KEK.
5. Store the challenge, identity, salt, nonce, and wrapped DEK in authenticated
   XSec metadata. The Windows Hello private key remains non-exportable.

The stored challenge and envelope are not secrets. Security depends on Windows
requiring user verification before `RequestSignAsync` can reproduce the
signature needed to derive the KEK. XSec does not use a separate yes/no
authorization call followed by an independently readable CNG or Credential
Manager key.

This model protects a locked, persistent XSec key from an attacker that can read
the metadata but cannot successfully invoke the enrolled Windows Hello
credential. It does not protect against:

- administrator or kernel compromise;
- code injection into an already unlocked host process;
- capture of the derived KEK, DEK, or deterministic signature from process
  memory;
- a malicious or spoofed user-verification prompt that the user approves;
- rollback of the complete XSec storage to an older valid snapshot.

The host application remains responsible for process hardening, disabling core
dumps where applicable, limiting diagnostic access, and promptly locking or
dropping unlocked `XSec` instances.

## Persistent envelope

The Windows payload is the `XSecSP` version 2 envelope defined in
`crates/xsec/SYSTEM_PROTECTOR.md`. Its identity, challenge, salt, nonce, and
ciphertext header are authenticated by AES-GCM. Each enrollment uses a fresh
challenge, salt, and nonce. Signature bytes and derived KEKs are temporary and
must be zeroized after use.

The credential name is derived from the hashed caller identity. Raw caller
identities are not placed in credential names or metadata.

## Lifecycle

- Enrollment creates or opens the identity-specific Windows Hello credential,
  prompts for a signature, and writes the wrapped DEK only after successful user
  verification.
- Unlock opens the existing credential and performs `RequestSignAsync` for the
  stored challenge on every call.
- Removing the system protector deletes the Windows Hello credential before
  committing metadata that no longer references it.
- Destroying initialized XSec storage deletes the Windows Hello credential
  before deleting metadata.
- Missing or reset credentials invalidate the old payload. XSec must never
  silently create a replacement while unlocking.

If credential deletion succeeds but the following metadata write fails, the
operation fails closed: password or another remaining protector is required to
recover and repair the metadata.

## Required runtime verification

Compilation and unit tests do not prove Windows Hello behavior. Before release,
run these checks on every supported Windows baseline:

1. Enroll and unlock with the configured Windows Hello methods.
2. Restart the process and unlock the persisted envelope.
3. Verify repeated signatures for the same credential and challenge are stable.
4. Cancel and fail the prompt and confirm no DEK is returned.
5. Reset/delete the Windows Hello credential and confirm the old payload fails.
6. Remove the system protector and confirm an old metadata snapshot can no
   longer unlock through that credential.
7. Attempt the direct bypass path without `RequestSignAsync` and confirm the
   envelope cannot be opened.

No runtime security claim should be made until these device checks pass.

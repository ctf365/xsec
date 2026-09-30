# XSec

XSec is a cross-platform data encryption library. It generates and manages
data-encryption keys (DEKs), protects them with password or system/KMS
protectors, and provides authenticated AES-256-GCM encryption.

Business ciphertext is owned by the caller. `XSecStorage` stores only XSec
metadata.

## Features

- Random-DEK and random-nonce AES-256-GCM encryption
- User AAD authenticated together with the ciphertext header
- Argon2id password protector with blocking work dispatched through Tokio
- Canonical binary metadata authenticated with HKDF/HMAC-SHA256
- Extensible asynchronous `XSecStorage` and `XSecProtector` interfaces
- `SecretBox` and `Zeroizing` for sensitive keys and decrypted data
- Optional atomic file storage with an exclusive lifetime lock
- Stable, platform-independent storage and protector error categories

## Features and platform notes

The default feature set enables `file-storage` and `password-protector`.
`system-protector` is opt-in and controls only whether `XSecSystemProtector` is
compiled and exported. It does not add system-specific methods to `XSec`.
When enabled, `XSecSystemProtector` delegates key management and ECIES to
[`hardware-enclave`](https://github.com/godaddy/hardware-enclave). XSec keeps
its own identity-bound payload and error model. The `XSecProtector` trait stays
unchanged. Backends are selected as follows:

| Platform | System protection |
| --- | --- |
| Windows | TPM 2.0 through CNG; platform-default user verification |
| macOS | Secure Enclave; platform-default user verification |
| Linux | System keyring by default; optional native TPM 2.0 or WSL TPM bridge |
| Other targets | `Unavailable` |

Enable `system-protector-linux-tpm` to compile the native Linux TPM backend.
Linux builds using `system-protector` require the system D-Bus and TPM 2.0
development libraries with the current `hardware-enclave` dependency feature
graph. The `system-protector-linux-tpm` feature enables native TPM selection;
the upstream crate currently compiles the TSS dependency even when that backend
is disabled. Linux backends do not enforce biometric or user-presence
verification. The keyring backend protects keys at rest but is not hardware
isolation.

`XSecSystemProtector::with_options` can require a hardware backend, force the
Linux keyring, or select an authentication policy. `HardwareOnly` fails closed
if the selected backend is a keyring or Windows DPAPI fallback. The default
`Automatic` policy permits Linux keyring fallback. `PlatformDefault` requests
user verification on macOS and Windows and no prompt on Linux.

Real prompts, credentials, desktop agents, and secure hardware must be tested
on the target device; a successful cross-compilation is not runtime evidence.

```rust
use xsec::{
    SystemAuthenticationPolicy, SystemBackendPreference, SystemProtectorOptions,
    XSecSystemProtector,
};

let protector = XSecSystemProtector::with_options(
    "my-application",
    SystemProtectorOptions {
        backend: SystemBackendPreference::HardwareOnly,
        authentication: SystemAuthenticationPolicy::PlatformDefault,
    },
)?;
```

## Quick start

```rust
use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("data/account.xsec.keys");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);
    let mut xsec = XSec::new();
    xsec.load(storage).await?;
    if !xsec.is_initialized() {
        xsec.create(&protector).await?;
    }
    let ciphertext = xsec.encrypt_with_aad(b"alice@example.com", b"user:123/profile/email")?;
    xsec.lock()?;
    xsec.unlock(&protector).await?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, b"user:123/profile/email")?;
    assert_eq!(plaintext.as_slice(), b"alice@example.com");
    Ok(())
}
```

The Chinese version is [`README.zh-CN.md`](README.zh-CN.md). The workspace
entry point is [`../../README.md`](../../README.md).

## Lifecycle

An `XSec` instance owns one storage object and moves through these states:

```text
new → load → uninitialized → create → unlocked ↔ locked
                                  └──────────────→ destroyed
```

Use `create` only for new storage and `unlock` for existing metadata. Encryption
and decryption require the unlocked state. `lock` clears the in-memory DEK;
`destroy` removes the current metadata but cannot erase backups or snapshots.

`XSecStorage` stores XSec metadata only. Callers remain responsible for storing
business ciphertext. `XSecProtector` implementations wrap and unwrap the DEK;
custom protectors are trusted code and must not log or retain the plaintext key.

`encrypt_with_aad` authenticates caller-supplied context without encrypting it.
Use stable, non-secret identifiers such as record IDs and field names. Every
encryption operation generates a fresh nonce.

## Security boundaries

- Password strength determines resistance to offline guessing of stolen metadata.
- `destroy` removes current metadata but cannot guarantee physical erasure from disks, backups, or snapshots.
- Version 1 does not provide rollback protection, DEK rotation, or multi-device synchronization.
- A third-party `XSecProtector` can access the plaintext DEK and must be trusted.
- Losing the storage metadata makes protected data unrecoverable unless a valid backup exists.

## License

Apache-2.0

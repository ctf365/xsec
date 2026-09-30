# XSec Workspace

XSec is a cross-platform data encryption workspace containing:

- `crates/xsec`: the core encryption and key-protection library;
- `crates/xsec-cli`: a command-line tool powered by `xsec`.

## Build and test

```text
cargo check --workspace
cargo test --workspace
```

The workspace currently contains two crates. `xsec` is the reusable library;
`xsec-cli` is the dotenv-oriented command-line frontend. The library's system
protector can use the `hardware-enclave` backends for Windows TPM 2.0, macOS
Secure Enclave, and Linux TPM/system keyring. Linux keyring protects keys at
rest but does not provide hardware isolation or user-presence verification.
Enable `system-protector-linux-tpm` to select native Linux TPM support. Platform
prompts and hardware behavior require validation on the corresponding device;
see [`crates/xsec/README.md`](crates/xsec/README.md) for build requirements and
backend options.

## CLI quick start

The Cargo package is `xsec-cli` and the installed executable is `xsec`.

```text
cargo run -p xsec-cli --bin xsec -- init
cargo run -p xsec-cli --bin xsec -- encrypt -i .env -o .xsec
cargo run -p xsec-cli --bin xsec -- run -f .xsec -- your-command
```

Read, set, or remove one value:

```text
cargo run -p xsec-cli --bin xsec -- get API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- set API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- del API_TOKEN -f .xsec
```

The encrypted environment file preserves dotenv structure. Protected values use
the reserved `xsec:<base64url-no-padding>` format.

```text
.env                plaintext input; do not commit
.xsec               encrypted dotenv environment
.xsec.production    encrypted production environment
.xsec.keys          protected DEK metadata; do not commit
```

After initialization, supported platforms can add a system protector:

```text
cargo run -p xsec-cli --bin xsec -- protector add system --identity your-project-id
```

See [`crates/xsec/README.md`](crates/xsec/README.md) and
[`crates/xsec-cli/README.md`](crates/xsec-cli/README.md) for package-specific
details. The Chinese version is [`README.zh-CN.md`](README.zh-CN.md).

## Security scope

XSec protects data while the application and operating-system security boundary
are trusted. It does not provide rollback protection, multi-device
synchronization, or automatic DEK rotation and ciphertext migration. Do not
commit `.env`, `.xsec.keys`, or other plaintext and key-storage files.

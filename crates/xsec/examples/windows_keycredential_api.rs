//! Direct Windows KeyCredentialManager cross-process experiment.
//!
//! This example calls Windows APIs directly and does not use XSec storage,
//! envelopes, protectors, or decryption. Run `setup` once, then run `sign-a`
//! and `sign-b` as separate processes. Compare their signature SHA-256 values.

use std::{env, error::Error};

use sha2::{Digest, Sha256};
use windows::{
    Security::{
        Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus},
        Cryptography::CryptographicBuffer,
    },
    core::{Array, HSTRING},
};

const CREDENTIAL_NAME: &str = "xsec-direct-api-cross-process-test";
const CHALLENGE: &[u8] = b"fixed-windows-keycredential-cross-process-challenge-v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let action = env::args().nth(1).unwrap_or_else(|| "help".into());
    match action.as_str() {
        "setup" => setup().await?,
        "sign-a" | "sign-b" => sign(&action).await?,
        "delete" => delete().await?,
        _ => usage(),
    }
    Ok(())
}

async fn setup() -> Result<(), Box<dyn Error>> {
    if !ensure_supported().await? {
        print_unsupported_requirements();
        return Ok(());
    }
    let name = HSTRING::from(CREDENTIAL_NAME);
    match KeyCredentialManager::DeleteAsync(&name)?.await {
        Ok(()) => println!("Removed the previous test credential."),
        Err(error) if is_not_found(&error) => {}
        Err(error) => return Err(error.into()),
    }

    let result =
        KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)?
            .await?;
    match result.Status()? {
        KeyCredentialStatus::Success => {
            println!("Created credential `{CREDENTIAL_NAME}` through Windows APIs.");
            println!("Now run sign-a and sign-b in separate processes.");
            Ok(())
        }
        status => Err(format!("credential creation returned {status:?}").into()),
    }
}

async fn sign(label: &str) -> Result<(), Box<dyn Error>> {
    if !ensure_supported().await? {
        print_unsupported_requirements();
        return Ok(());
    }
    let name = HSTRING::from(CREDENTIAL_NAME);
    let result = KeyCredentialManager::OpenAsync(&name)?.await?;
    match result.Status()? {
        KeyCredentialStatus::Success => {}
        status => return Err(format!("credential open returned {status:?}").into()),
    }
    let credential = result.Credential()?;
    let input = CryptographicBuffer::CreateFromByteArray(CHALLENGE)?;
    let response = credential.RequestSignAsync(&input)?.await?;
    match response.Status()? {
        KeyCredentialStatus::Success => {}
        status => return Err(format!("RequestSignAsync returned {status:?}").into()),
    }
    let buffer = response.Result()?;
    let length = buffer.Length()? as usize;
    let mut signature = Array::<u8>::with_len(length);
    CryptographicBuffer::CopyToByteArray(&buffer, &mut signature)?;
    let digest = Sha256::digest(&*signature);
    signature.fill(0);
    println!("{label}: signature SHA-256 {}", hex(&digest));
    Ok(())
}

async fn delete() -> Result<(), Box<dyn Error>> {
    let name = HSTRING::from(CREDENTIAL_NAME);
    match KeyCredentialManager::DeleteAsync(&name)?.await {
        Ok(()) => println!("Deleted credential `{CREDENTIAL_NAME}`."),
        Err(error) if is_not_found(&error) => println!("Credential was already absent."),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn ensure_supported() -> Result<bool, Box<dyn Error>> {
    Ok(KeyCredentialManager::IsSupportedAsync()?.await?)
}

fn print_unsupported_requirements() {
    println!("Windows reports KeyCredentialManager is not supported for this user/device.");
    println!(
        "Microsoft documents that key provisioning requires a linked Microsoft account and a configured Windows Hello unlock gesture (PIN or biometrics)."
    );
}

fn is_not_found(error: &windows::core::Error) -> bool {
    // KeyCredentialManager::DeleteAsync may report NTE_NO_KEY when the
    // credential has never been created on this device.
    matches!(error.code().0 as u32, 0x8009000D | 0x80090016 | 0x80070490)
}

fn usage() {
    println!(
        "Usage: cargo run -p xsec --example windows_keycredential_api --features system-protector -- <setup|sign-a|sign-b|delete>"
    );
    println!(
        "Use setup once, then run sign-a and sign-b as separate processes and compare the digests."
    );
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

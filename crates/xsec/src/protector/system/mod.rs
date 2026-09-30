#[cfg(target_os = "linux")]
use hardware_enclave::LinuxConfig;
#[cfg(target_os = "macos")]
use hardware_enclave::MacOsConfig;
use hardware_enclave::{
    AccessPolicy, BackendKind, EnclaveConfig, EncryptorHandle, Error as EnclaveError,
    PlatformConfig, create_encryptor,
};
#[cfg(target_os = "windows")]
use hardware_enclave::{WindowsConfig, WindowsSoftwareFallback};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{XSecProtector, XSecProtectorError, XSecProtectorResult};

const MAX_IDENTITY_SIZE: usize = 4096;
const MAGIC: &[u8; 6] = b"XSecHE";
const PAYLOAD_VERSION: u16 = 1;
const IDENTITY_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const BACKEND_SIZE: usize = 1;
const OPTIONS_SIZE: usize = 2;
const PAYLOAD_HEADER_SIZE: usize = MAGIC.len() + 2 + BACKEND_SIZE + OPTIONS_SIZE + IDENTITY_SIZE;
const ENCRYPTED_PLAINTEXT_SIZE: usize = IDENTITY_SIZE + BACKEND_SIZE + OPTIONS_SIZE + KEY_SIZE;

/// Selects how the system protector chooses its platform backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemBackendPreference {
    /// Let hardware-enclave choose the native backend. Linux can use TPM,
    /// the WSL TPM bridge, or the system keyring according to build/runtime.
    #[default]
    Automatic,
    /// Require an actual hardware-backed backend. On Linux, the optional
    /// `system-protector-linux-tpm` feature is required for native TPM use.
    HardwareOnly,
    /// Force the Linux system-keyring backend. Unsupported on other targets.
    KeyringOnly,
}

/// User authentication policy requested for hardware key use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SystemAuthenticationPolicy {
    /// Use user verification on macOS and Windows; use no prompt on Linux,
    /// where the selected hardware-enclave backends do not enforce it.
    #[default]
    PlatformDefault,
    /// Require no user interaction.
    None,
    /// Allow the platform's supported user verification methods.
    UserVerification,
    /// Require biometric verification where the platform backend supports it.
    BiometricOnly,
}

/// Concrete backend selected by hardware-enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProtectorBackend {
    SecureEnclave,
    Tpm,
    TpmBridge,
    Keyring,
    WindowsDpapi,
}

/// Configuration for [`XSecSystemProtector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemProtectorOptions {
    pub backend: SystemBackendPreference,
    pub authentication: SystemAuthenticationPolicy,
}

/// Platform-backed encryption protector.
///
/// The public `XSecProtector` contract stays independent of the platform
/// backend. hardware-enclave owns native key creation, persistence, and ECIES;
/// XSec owns identity binding and its serialized payload envelope.
pub struct XSecSystemProtector {
    identity: [u8; IDENTITY_SIZE],
    key_label: String,
    app_name: &'static str,
    options: SystemProtectorOptions,
}

impl XSecSystemProtector {
    /// Create a system protector with platform defaults.
    pub fn new(identity: impl Into<String>) -> XSecProtectorResult<Self> {
        Self::with_options(identity, SystemProtectorOptions::default())
    }

    /// Create a system protector with an explicit backend and authentication
    /// policy. Construction is side-effect free; the native key is initialized
    /// on availability check or first use.
    pub fn with_options(
        identity: impl Into<String>,
        options: SystemProtectorOptions,
    ) -> XSecProtectorResult<Self> {
        let identity = identity.into();
        if identity.len() > MAX_IDENTITY_SIZE {
            return Err(XSecProtectorError::InvalidData);
        }
        validate_options(options)?;

        let mut hasher = Sha256::new();
        hasher.update(b"xsec:system-protector:v2");
        hasher.update((identity.len() as u32).to_be_bytes());
        hasher.update(identity.as_bytes());
        let identity: [u8; IDENTITY_SIZE] = hasher.finalize().into();

        // 64 lowercase hex characters satisfy hardware-enclave's label rules
        // and retain all 256 bits of identity separation.
        let key_label = hex(&identity);
        let app_name = app_name(options.backend);

        Ok(Self {
            identity,
            key_label,
            app_name,
            options,
        })
    }

    pub(crate) fn from_payload(payload: &[u8]) -> XSecProtectorResult<Self> {
        let parsed = parse_payload(payload, None)?;
        Ok(Self {
            identity: parsed.identity,
            key_label: hex(&parsed.identity),
            app_name: app_name(parsed.options.backend),
            options: parsed.options,
        })
    }

    /// Initialize and probe the selected platform backend.
    pub async fn check_availability(&self) -> XSecProtectorResult<()> {
        self.initialize_backend().map(|_| ())
    }

    /// Return the backend selected for this protector.
    pub fn backend(&self) -> XSecProtectorResult<SystemProtectorBackend> {
        self.initialize_backend().map(|(_, backend)| backend)
    }

    /// Delete this identity's platform key.
    pub async fn delete(&self) -> XSecProtectorResult<()> {
        let (encryptor, _) = self.initialize_backend()?;
        match encryptor.delete_key(&self.key_label) {
            Ok(()) => Ok(()),
            Err(EnclaveError::KeyNotFound { .. }) => Ok(()),
            Err(error) => Err(map_enclave_error(&error, false)),
        }
    }

    fn initialize_backend(&self) -> XSecProtectorResult<(EncryptorHandle, SystemProtectorBackend)> {
        let mut config = EnclaveConfig::new(self.app_name, &self.key_label);
        config.access_policy = Some(access_policy(self.options.authentication)?);

        #[cfg(target_os = "macos")]
        {
            config.platform = PlatformConfig::MacOs(MacOsConfig::default());
        }

        #[cfg(target_os = "windows")]
        {
            config.platform = PlatformConfig::Windows(WindowsConfig {
                software_fallback: WindowsSoftwareFallback::Disabled,
                ..WindowsConfig::default()
            });
        }

        #[cfg(target_os = "linux")]
        {
            config.platform = PlatformConfig::Linux(LinuxConfig {
                force_keyring: self.options.backend == SystemBackendPreference::KeyringOnly,
                ..LinuxConfig::default()
            });
        }

        let encryptor =
            create_encryptor(&config).map_err(|error| map_enclave_error(&error, false))?;
        let backend = map_backend_kind(encryptor.backend_kind());
        if !backend_allowed(self.options.backend, backend) {
            // HardwareOnly uses a separate app namespace, so this cleanup can
            // remove only a fallback key created for this failed selection.
            drop(encryptor.delete_key(&self.key_label));
            return Err(XSecProtectorError::Unsupported);
        }

        Ok((encryptor, backend))
    }
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        "system"
    }

    async fn wrap_key<'a>(
        &'a self,
        key: &'a SecretBox<[u8; KEY_SIZE]>,
    ) -> XSecProtectorResult<Vec<u8>> {
        let (encryptor, backend) = self.initialize_backend()?;
        let backend_id = backend_id(backend);

        // Encrypt identity and backend metadata together with the DEK. The
        // outer header permits early rejection; the encrypted copy authenticates
        // those fields as part of the hardware-enclave AEAD ciphertext.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ENCRYPTED_PLAINTEXT_SIZE));
        plaintext.extend_from_slice(&self.identity);
        plaintext.push(backend_id);
        plaintext.push(backend_preference_id(self.options.backend));
        plaintext.push(authentication_policy_id(self.options.authentication));
        plaintext.extend_from_slice(key.expose_secret());

        let ciphertext = encryptor
            .encrypt(&self.key_label, &plaintext)
            .map_err(|error| map_enclave_error(&error, false))?;

        let mut payload = Vec::with_capacity(PAYLOAD_HEADER_SIZE + ciphertext.len());
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        payload.push(backend_id);
        payload.push(backend_preference_id(self.options.backend));
        payload.push(authentication_policy_id(self.options.authentication));
        payload.extend_from_slice(&self.identity);
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    async fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> XSecProtectorResult<SecretBox<[u8; KEY_SIZE]>> {
        let parsed = parse_payload(payload, Some(&self.identity))?;
        if parsed.options != self.options {
            return Err(XSecProtectorError::Incompatible);
        }
        let (encryptor, actual_backend) = self.initialize_backend()?;
        if actual_backend != parsed.backend {
            return Err(XSecProtectorError::Incompatible);
        }

        let plaintext = encryptor
            .decrypt(&self.key_label, parsed.ciphertext)
            .map_err(|error| map_enclave_error(&error, true))?;
        if plaintext.len() != ENCRYPTED_PLAINTEXT_SIZE
            || plaintext[..IDENTITY_SIZE] != self.identity
            || plaintext[IDENTITY_SIZE] != backend_id(parsed.backend)
            || plaintext[IDENTITY_SIZE + 1] != backend_preference_id(parsed.options.backend)
            || plaintext[IDENTITY_SIZE + 2]
                != authentication_policy_id(parsed.options.authentication)
        {
            return Err(XSecProtectorError::AuthenticationFailed);
        }

        let mut key = Box::new([0; KEY_SIZE]);
        key.copy_from_slice(&plaintext[IDENTITY_SIZE + BACKEND_SIZE + OPTIONS_SIZE..]);
        Ok(SecretBox::new(key))
    }

    async fn delete(&self) -> XSecProtectorResult<()> {
        XSecSystemProtector::delete(self).await
    }
}

fn validate_options(options: SystemProtectorOptions) -> XSecProtectorResult<()> {
    #[cfg(not(target_os = "linux"))]
    if options.backend == SystemBackendPreference::KeyringOnly {
        return Err(XSecProtectorError::Unsupported);
    }

    #[cfg(target_os = "linux")]
    if options.authentication != SystemAuthenticationPolicy::PlatformDefault
        && options.authentication != SystemAuthenticationPolicy::None
    {
        // hardware-enclave documents no user-presence enforcement for Linux
        // TPM/keyring backends. Reject requests instead of silently weakening.
        return Err(XSecProtectorError::Unsupported);
    }

    Ok(())
}

fn access_policy(policy: SystemAuthenticationPolicy) -> XSecProtectorResult<AccessPolicy> {
    match policy {
        SystemAuthenticationPolicy::PlatformDefault => {
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            {
                Ok(AccessPolicy::Any)
            }
            #[cfg(target_os = "linux")]
            {
                Ok(AccessPolicy::None)
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
            {
                Err(XSecProtectorError::Unavailable)
            }
        }
        SystemAuthenticationPolicy::None => Ok(AccessPolicy::None),
        SystemAuthenticationPolicy::UserVerification => Ok(AccessPolicy::Any),
        SystemAuthenticationPolicy::BiometricOnly => Ok(AccessPolicy::BiometricOnly),
    }
}

fn backend_allowed(preference: SystemBackendPreference, backend: SystemProtectorBackend) -> bool {
    match preference {
        SystemBackendPreference::Automatic => backend != SystemProtectorBackend::WindowsDpapi,
        SystemBackendPreference::HardwareOnly => matches!(
            backend,
            SystemProtectorBackend::SecureEnclave
                | SystemProtectorBackend::Tpm
                | SystemProtectorBackend::TpmBridge
        ),
        SystemBackendPreference::KeyringOnly => backend == SystemProtectorBackend::Keyring,
    }
}

fn map_backend_kind(kind: BackendKind) -> SystemProtectorBackend {
    match kind {
        BackendKind::SecureEnclave => SystemProtectorBackend::SecureEnclave,
        BackendKind::Tpm => SystemProtectorBackend::Tpm,
        BackendKind::TpmBridge => SystemProtectorBackend::TpmBridge,
        BackendKind::Keyring => SystemProtectorBackend::Keyring,
        BackendKind::WindowsDpapi => SystemProtectorBackend::WindowsDpapi,
    }
}

fn backend_id(backend: SystemProtectorBackend) -> u8 {
    match backend {
        SystemProtectorBackend::SecureEnclave => 1,
        SystemProtectorBackend::Tpm => 2,
        SystemProtectorBackend::TpmBridge => 3,
        SystemProtectorBackend::Keyring => 4,
        SystemProtectorBackend::WindowsDpapi => 5,
    }
}

fn backend_from_id(id: u8) -> XSecProtectorResult<SystemProtectorBackend> {
    match id {
        1 => Ok(SystemProtectorBackend::SecureEnclave),
        2 => Ok(SystemProtectorBackend::Tpm),
        3 => Ok(SystemProtectorBackend::TpmBridge),
        4 => Ok(SystemProtectorBackend::Keyring),
        5 => Ok(SystemProtectorBackend::WindowsDpapi),
        _ => Err(XSecProtectorError::InvalidData),
    }
}

struct ParsedPayload<'a> {
    identity: [u8; IDENTITY_SIZE],
    backend: SystemProtectorBackend,
    options: SystemProtectorOptions,
    ciphertext: &'a [u8],
}

fn parse_payload<'a>(
    payload: &'a [u8],
    expected_identity: Option<&[u8; IDENTITY_SIZE]>,
) -> XSecProtectorResult<ParsedPayload<'a>> {
    if payload.len() <= PAYLOAD_HEADER_SIZE || payload.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(XSecProtectorError::InvalidData);
    }
    let version_start = MAGIC.len();
    let version = u16::from_be_bytes(
        payload[version_start..version_start + 2]
            .try_into()
            .map_err(|_| XSecProtectorError::InvalidData)?,
    );
    if version != PAYLOAD_VERSION {
        return Err(XSecProtectorError::Unsupported);
    }

    let backend = backend_from_id(payload[version_start + 2])?;
    let options_start = version_start + 2 + BACKEND_SIZE;
    let options = SystemProtectorOptions {
        backend: backend_preference_from_id(payload[options_start])?,
        authentication: authentication_policy_from_id(payload[options_start + 1])?,
    };
    let identity_start = options_start + OPTIONS_SIZE;
    let identity_end = identity_start + IDENTITY_SIZE;
    let identity: [u8; IDENTITY_SIZE] = payload
        .get(identity_start..identity_end)
        .ok_or(XSecProtectorError::InvalidData)?
        .try_into()
        .map_err(|_| XSecProtectorError::InvalidData)?;
    if expected_identity.is_some_and(|expected| &identity != expected) {
        return Err(XSecProtectorError::KeyInvalidated);
    }
    Ok(ParsedPayload {
        identity,
        backend,
        options,
        ciphertext: &payload[identity_end..],
    })
}

fn app_name(preference: SystemBackendPreference) -> &'static str {
    match preference {
        SystemBackendPreference::Automatic => "xsec",
        SystemBackendPreference::HardwareOnly => "xsec-hardware",
        SystemBackendPreference::KeyringOnly => "xsec-keyring",
    }
}

fn backend_preference_id(preference: SystemBackendPreference) -> u8 {
    match preference {
        SystemBackendPreference::Automatic => 1,
        SystemBackendPreference::HardwareOnly => 2,
        SystemBackendPreference::KeyringOnly => 3,
    }
}

fn backend_preference_from_id(id: u8) -> XSecProtectorResult<SystemBackendPreference> {
    match id {
        1 => Ok(SystemBackendPreference::Automatic),
        2 => Ok(SystemBackendPreference::HardwareOnly),
        3 => Ok(SystemBackendPreference::KeyringOnly),
        _ => Err(XSecProtectorError::InvalidData),
    }
}

fn authentication_policy_id(policy: SystemAuthenticationPolicy) -> u8 {
    match policy {
        SystemAuthenticationPolicy::PlatformDefault => 1,
        SystemAuthenticationPolicy::None => 2,
        SystemAuthenticationPolicy::UserVerification => 3,
        SystemAuthenticationPolicy::BiometricOnly => 4,
    }
}

fn authentication_policy_from_id(id: u8) -> XSecProtectorResult<SystemAuthenticationPolicy> {
    match id {
        1 => Ok(SystemAuthenticationPolicy::PlatformDefault),
        2 => Ok(SystemAuthenticationPolicy::None),
        3 => Ok(SystemAuthenticationPolicy::UserVerification),
        4 => Ok(SystemAuthenticationPolicy::BiometricOnly),
        _ => Err(XSecProtectorError::InvalidData),
    }
}

fn map_enclave_error(error: &EnclaveError, decrypting: bool) -> XSecProtectorError {
    match error {
        EnclaveError::NotAvailable => XSecProtectorError::Unavailable,
        EnclaveError::KeyNotFound { .. } => XSecProtectorError::KeyNotFound,
        EnclaveError::AuthDenied { .. } => XSecProtectorError::AccessDenied,
        EnclaveError::AuthRequired { .. } => XSecProtectorError::UserVerificationRequired,
        EnclaveError::UserCancelled { .. } => XSecProtectorError::AuthenticationCancelled,
        EnclaveError::PolicyNotSupported { .. } => XSecProtectorError::Unsupported,
        EnclaveError::PolicyMismatch { .. } => XSecProtectorError::KeyInvalidated,
        EnclaveError::InvalidLabel { .. } => XSecProtectorError::InvalidData,
        EnclaveError::DecryptFailed { .. } if decrypting => {
            XSecProtectorError::AuthenticationFailed
        }
        EnclaveError::Config(_) => XSecProtectorError::Unsupported,
        _ => XSecProtectorError::Internal,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(identity: [u8; IDENTITY_SIZE]) -> Vec<u8> {
        let mut payload = Vec::from(MAGIC.as_slice());
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        payload.push(backend_id(SystemProtectorBackend::Tpm));
        payload.push(backend_preference_id(SystemBackendPreference::HardwareOnly));
        payload.push(authentication_policy_id(
            SystemAuthenticationPolicy::UserVerification,
        ));
        payload.extend_from_slice(&identity);
        payload.push(0xaa); // opaque hardware-enclave ciphertext
        payload
    }

    #[test]
    fn payload_round_trips_system_options_and_identity() {
        let identity = [0x5a; IDENTITY_SIZE];
        let bytes = payload(identity);
        let parsed = parse_payload(&bytes, Some(&identity)).unwrap();
        assert_eq!(parsed.backend, SystemProtectorBackend::Tpm);
        assert_eq!(
            parsed.options,
            SystemProtectorOptions {
                backend: SystemBackendPreference::HardwareOnly,
                authentication: SystemAuthenticationPolicy::UserVerification,
            }
        );
        assert_eq!(parsed.identity, identity);
        assert_eq!(parsed.ciphertext, &[0xaa]);
    }

    #[test]
    fn payload_rejects_identity_mismatch_and_unsupported_version() {
        let identity = [0x5a; IDENTITY_SIZE];
        assert!(matches!(
            parse_payload(&payload(identity), Some(&[0x6b; IDENTITY_SIZE])),
            Err(XSecProtectorError::KeyInvalidated)
        ));

        let mut payload = payload(identity);
        payload[MAGIC.len() + 1] = 2;
        assert!(matches!(
            parse_payload(&payload, Some(&identity)),
            Err(XSecProtectorError::Unsupported)
        ));
    }

    #[test]
    fn hardware_only_rejects_the_keyring_backend() {
        assert!(!backend_allowed(
            SystemBackendPreference::HardwareOnly,
            SystemProtectorBackend::Keyring
        ));
        assert!(backend_allowed(
            SystemBackendPreference::HardwareOnly,
            SystemProtectorBackend::Tpm
        ));
    }
}

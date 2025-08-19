#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/ArdentEmpiricist/enc_file/main/assets/logo.png"
)]
//! # enc_file — password-based authenticated encryption for files.
//!
//! `enc_file` is a Rust library for encrypting, decrypting, and hashing files or byte arrays.
//! It supports modern AEAD ciphers (XChaCha20-Poly1305, AES-256-GCM-SIV) with Argon2id key derivation.
//!
//! ## Features
//! - **File and byte array encryption/decryption**
//! - **Streaming encryption** for large files (constant memory usage)
//! - **Multiple AEAD algorithms**: XChaCha20-Poly1305, AES-256-GCM-SIV
//! - **Password-based key derivation** using Argon2id
//! - **Key map management** for named symmetric keys
//! - **Flexible hashing API** with support for BLAKE3, SHA2, SHA3, Blake2b, XXH3, and CRC32
//! - **ASCII armor** for encrypted data (Base64 encoding)
//!
//! ## Example: Encrypt and decrypt a byte array
//! ```no_run
//! use enc_file::{encrypt_bytes, decrypt_bytes, EncryptOptions, AeadAlg};
//! use secrecy::SecretString;
//!
//! let password = SecretString::new("mypassword".into());
//! let opts = EncryptOptions {
//!     alg: AeadAlg::XChaCha20Poly1305,
//!     ..Default::default()
//! };
//!
//! let ciphertext = encrypt_bytes(b"Hello, world!", password.clone(), &opts).unwrap();
//! let plaintext = decrypt_bytes(&ciphertext, password).unwrap();
//! assert_eq!(plaintext, b"Hello, world!");
//! ```
//!
//! ## Example: Hash a file
//! ```no_run
//! use enc_file::{hash_file, HashAlg};
//! use std::path::Path;
//!
//! let digest = hash_file(Path::new("myfile.txt"), HashAlg::Blake3).unwrap();
//! println!("Hash: {}", enc_file::to_hex_lower(&digest));
//! ```
//!
//! See function-level documentation for more details.
//!
//! Safety notes
//! - The crate is not audited or reviewed! Protects data at rest. Does not defend against compromised hosts/side channels.

mod types;
mod format;
mod kdf;
mod crypto;
mod armor;

// Re-export public API from modules
pub use types::*;
pub use crypto::{encrypt_bytes, decrypt_bytes};
pub use armor::looks_armored;

// Temporary placeholder for the rest - we'll move these in subsequent steps
// TODO: Remove these placeholder functions once all modules are complete

/// Temporary placeholder function
pub fn encrypt_file(
    _input: &std::path::Path,
    _output: Option<&std::path::Path>,
    _password: secrecy::SecretString,
    _opts: EncryptOptions,
) -> Result<std::path::PathBuf, EncFileError> {
    unimplemented!("Will be moved to file module")
}

/// Temporary placeholder function
pub fn decrypt_file(
    _input: &std::path::Path,
    _output: Option<&std::path::Path>,
    _password: secrecy::SecretString,
) -> Result<std::path::PathBuf, EncFileError> {
    unimplemented!("Will be moved to file module")
}

/// Temporary placeholder function
pub fn load_keymap(
    _path: &std::path::Path,
    _password: secrecy::SecretString,
) -> Result<KeyMap, EncFileError> {
    unimplemented!("Will be moved to keymap module")
}

/// Temporary placeholder function
pub fn save_keymap(
    _path: &std::path::Path,
    _password: secrecy::SecretString,
    _map: &KeyMap,
    _opts: &EncryptOptions,
) -> Result<(), EncFileError> {
    unimplemented!("Will be moved to keymap module")
}

/// Temporary placeholder enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlg {
    #[default]
    Blake3,
}

/// Temporary placeholder function
pub fn hash_file(
    _path: &std::path::Path,
    _alg: HashAlg,
) -> Result<Vec<u8>, EncFileError> {
    unimplemented!("Will be moved to hash module")
}

/// Temporary placeholder function
pub fn to_hex_lower(_bytes: &[u8]) -> String {
    unimplemented!("Will be moved to hash module")
}

/// Temporary placeholder function
pub fn encrypt_file_streaming(
    _input: &std::path::Path,
    _output: Option<&std::path::Path>,
    _password: secrecy::SecretString,
    _opts: EncryptOptions,
) -> Result<std::path::PathBuf, EncFileError> {
    unimplemented!("Will be moved to streaming module")
}

/// Temporary placeholder function
pub fn validate_chunk_size_for_streaming(_chunk_size: usize) -> Result<(), EncFileError> {
    unimplemented!("Will be moved to streaming module")
}

/// Temporary placeholder function
pub fn persist_tempfile_atomic(
    _tmp: tempfile::NamedTempFile,
    _out: &std::path::Path,
    _force: bool,
) -> Result<std::path::PathBuf, EncFileError> {
    unimplemented!("Will be moved to file module")
}

/// Temporary placeholder function
pub fn default_decrypt_output_path(_in_path: &std::path::Path) -> std::path::PathBuf {
    unimplemented!("Will be moved to file module")
}

// Keep tests at the end for now
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn round_trip_small_default() {
        let pw = SecretString::new("pw".into());
        let ct = encrypt_bytes(b"hi", pw.clone(), &EncryptOptions::default()).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, b"hi");
    }

    #[test]
    fn wrong_password_fails() {
        let ct = encrypt_bytes(
            b"data",
            SecretString::new("pw1".into()),
            &EncryptOptions::default(),
        )
        .unwrap();
        let bad = SecretString::new("pw2".into());
        assert!(matches!(decrypt_bytes(&ct, bad), Err(EncFileError::Crypto)));
    }

    #[test]
    fn armor_works() {
        use secrecy::SecretString;

        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions::default().with_armor(true);

        let ct = encrypt_bytes(b"abc", pw.clone(), &opts).unwrap();
        assert!(looks_armored(&ct));
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, b"abc");
    }
}
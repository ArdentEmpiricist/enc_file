//! Core encryption and decryption primitives.

use crate::types::{AeadAlg, EncFileError};
use aead::{Aead, KeyInit};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill as getrandom;
use zeroize::Zeroize;

/// AEAD authentication tag length (16 bytes for all supported algorithms).
pub const AEAD_TAG_LEN: usize = 16;

/// Get the nonce length for a given AEAD algorithm.
pub fn nonce_len_for(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::XChaCha20Poly1305 => 24,
        AeadAlg::Aes256GcmSiv => 12,
    }
}

/// Generate a cryptographically secure random nonce for the given algorithm.
pub fn generate_nonce(alg: AeadAlg) -> Result<Vec<u8>, EncFileError> {
    let mut nonce = vec![0u8; nonce_len_for(alg)];
    getrandom(&mut nonce).map_err(|_| EncFileError::Crypto)?;
    Ok(nonce)
}

/// Generate a cryptographically secure random salt.
pub fn generate_salt() -> Result<Vec<u8>, EncFileError> {
    let mut salt = vec![0u8; 16];
    getrandom(&mut salt).map_err(|_| EncFileError::Crypto)?;
    Ok(salt)
}

/// Encrypt plaintext using AEAD with the specified algorithm, key, and nonce.
///
/// # Arguments
///
/// * `alg` - The AEAD algorithm to use
/// * `key` - 32-byte encryption key
/// * `nonce_bytes` - Nonce of appropriate length for the algorithm
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// Encrypted ciphertext (includes authentication tag)
pub fn aead_encrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

/// Decrypt ciphertext using AEAD with the specified algorithm, key, and nonce.
///
/// # Arguments
///
/// * `alg` - The AEAD algorithm to use
/// * `key` - 32-byte decryption key (same as used for encryption)
/// * `nonce_bytes` - Nonce of appropriate length for the algorithm
/// * `ciphertext` - Data to decrypt (includes authentication tag)
///
/// # Returns
///
/// Decrypted plaintext if authentication succeeds
///
/// # Errors
///
/// Returns `EncFileError::Crypto` if decryption or authentication fails.
pub fn aead_decrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

/// Securely zeroize a key after use.
pub fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

/// Create an XChaCha20-Poly1305 cipher instance.
pub fn create_xchacha20poly1305_cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305, EncFileError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)
}

/// Create an AES-256-GCM-SIV cipher instance.
pub fn create_aes256gcmsiv_cipher(key: &[u8; 32]) -> Result<Aes256GcmSiv, EncFileError> {
    Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)
}
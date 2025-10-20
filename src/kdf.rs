//! Key derivation functionality with security validations.
//!
//! This module provides secure password-based key derivation using Argon2id
//! with comprehensive parameter validation to prevent weak configurations.
//!
//! # Security Guidelines
//!
//! When handling passwords and derived keys:
//! - Use `SecretString` from the `secrecy` crate for password storage
//! - Zeroize derived keys after use when possible
//! - Use strong Argon2id parameters appropriate for your security requirements
//! - Ensure salts are cryptographically random and unique per encryption

use crate::types::{EncFileError, KdfParams};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Minimum memory cost for Argon2id (64 MiB).
const MIN_MEMORY_COST_KIB: u32 = 65536;

/// Minimum time cost for Argon2id.
const MIN_TIME_COST: u32 = 3;

/// Maximum parallelism value (u24 max as supported by Argon2).
const MAX_PARALLELISM: u32 = 16_777_215;

/// Minimum salt length for security (8 bytes).
const MIN_SALT_LENGTH: usize = 8;

/// Derive a 32-byte key from a password using Argon2id with security validations.
///
/// This function validates all Argon2id parameters to ensure they meet minimum
/// security requirements before performing key derivation.
///
/// # Security Parameters
///
/// - **Memory cost**: Must be at least 8 KiB to resist TMTO attacks
/// - **Time cost**: Must be at least 1 iteration  
/// - **Parallelism**: Must be between 1 and 16,777,215 threads
/// - **Salt**: Must be at least 8 bytes long for uniqueness
///
/// # Arguments
///
/// * `password` - The password to derive from (securely wrapped)
/// * `params` - Argon2id parameters (validated for security)
/// * `salt` - Cryptographically random salt (validated for length)
///
/// # Returns
///
/// A 32-byte derived key suitable for symmetric encryption.
///
/// # Errors
///
/// Returns `EncFileError::Invalid` if any parameter fails validation:
/// - Memory cost too low (< 64 MiB)
/// - Time cost too low (< 3)  
/// - Parallelism out of range (< 1 or > 16,777,215)
/// - Salt too short (< 8 bytes)
/// - Internal Argon2 parameter validation fails
///
/// Returns `EncFileError::Crypto` if key derivation fails.
pub fn derive_key_argon2id(
    password: &SecretString,
    params: KdfParams,
    salt: &[u8],
) -> Result<[u8; 32], EncFileError> {
    // Validate salt length
    if salt.len() < MIN_SALT_LENGTH {
        return Err(EncFileError::Invalid("kdf: salt must be at least 8 bytes"));
    }

    // Validate memory cost
    if params.mem_kib < MIN_MEMORY_COST_KIB {
        return Err(EncFileError::Invalid(
            "kdf: memory cost must be at least 64 MiB",
        ));
    }

    // Validate time cost
    if params.t_cost < MIN_TIME_COST {
        return Err(EncFileError::Invalid("kdf: time cost must be at least 3"));
    }

    // Validate parallelism
    if params.parallelism == 0 || params.parallelism > MAX_PARALLELISM {
        return Err(EncFileError::Invalid(
            "kdf: parallelism must be between 1 and 16777215",
        ));
    }

    // Create Argon2 parameters
    let argon_params = Params::new(params.mem_kib, params.t_cost, params.parallelism, None)
        .map_err(|_| EncFileError::Invalid("kdf: invalid Argon2 params"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);

    // Perform key derivation
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, out.as_mut())
        .map_err(|_| EncFileError::Crypto)?;
    
    Ok(*out)
}

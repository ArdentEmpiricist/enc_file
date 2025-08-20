//! Key derivation functions.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};

use crate::types::{KdfParams, EncFileError};

/// Derive a 32-byte key using Argon2id with the given parameters.
///
/// # Security Notes
/// - Uses Argon2id algorithm (hybrid of Argon2i and Argon2d)
/// - Password is temporarily exposed for hashing but handled securely
/// - Derived key should be zeroized by caller after use
pub fn derive_key_argon2id(
    password: &SecretString,
    params: KdfParams,
    salt: &[u8],
) -> Result<[u8; 32], EncFileError> {
    // Validate parameters for security
    if params.mem_kib < 8 {
        return Err(EncFileError::Invalid("Argon2 memory cost too low (minimum 8 KiB)"));
    }
    if params.t_cost < 1 {
        return Err(EncFileError::Invalid("Argon2 time cost too low (minimum 1)"));
    }
    if params.parallelism < 1 || params.parallelism > 16777215 {
        return Err(EncFileError::Invalid("Argon2 parallelism out of range (1-16777215)"));
    }
    if salt.len() < 8 {
        return Err(EncFileError::Invalid("salt too short (minimum 8 bytes)"));
    }

    let argon_params = Params::new(params.mem_kib, params.t_cost, params.parallelism, None)
        .map_err(|_| EncFileError::Invalid("invalid Argon2 parameters"))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    
    // Temporarily expose password for hashing - this is necessary for Argon2
    // The password bytes are not stored and are cleaned up automatically
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|_| EncFileError::Crypto)?;
    
    Ok(out)
}
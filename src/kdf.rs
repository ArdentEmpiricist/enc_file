//! Key derivation functions.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};

use crate::types::{KdfParams, EncFileError};

pub fn derive_key_argon2id(
    password: &SecretString,
    params: KdfParams,
    salt: &[u8],
) -> Result<[u8; 32], EncFileError> {
    let argon_params = Params::new(params.mem_kib, params.time_cost, params.parallelism, None)
        .map_err(|_| EncFileError::Invalid("invalid Argon2 params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|_| EncFileError::Crypto)?;
    Ok(out)
}
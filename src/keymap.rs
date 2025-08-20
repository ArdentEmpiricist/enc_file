//! Named symmetric key map management.

use crate::types::{EncFileError, EncryptOptions, KeyMap};
use crate::file::write_all_atomic;
use secrecy::SecretString;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Load an encrypted key map from disk using a password.
///
/// The key map is expected to be an encrypted CBOR-encoded HashMap
/// created by `save_keymap`.
///
/// # Arguments
///
/// * `path` - Path to the encrypted key map file
/// * `password` - Password used to encrypt the key map
///
/// # Returns
///
/// The decrypted key map containing string names mapped to key data.
pub fn load_keymap(path: &Path, password: SecretString) -> Result<KeyMap, EncFileError> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let pt = crate::decrypt_bytes(&data, password)?;
    let map: KeyMap = serde_cbor::from_slice(&pt)?;
    Ok(map)
}

/// Save a key map to disk encrypted with a password.
///
/// The key map is CBOR-encoded and then encrypted using the provided options.
/// On Unix systems, the output file permissions are set to 0600 for security.
///
/// # Arguments
///
/// * `path` - Output path for the encrypted key map
/// * `password` - Password to encrypt the key map with
/// * `map` - The key map to save
/// * `opts` - Encryption options (streaming is not supported for key maps)
///
/// # Errors
///
/// Returns `EncFileError::Invalid` if streaming mode is requested, as key maps
/// don't support streaming encryption.
pub fn save_keymap(
    path: &Path,
    password: SecretString,
    map: &KeyMap,
    opts: &EncryptOptions,
) -> Result<(), EncFileError> {
    let pt = serde_cbor::to_vec(map)?;
    let bytes = if opts.stream {
        return Err(EncFileError::Invalid("keymap: streaming not supported"));
    } else {
        crate::encrypt_bytes(&pt, password, opts)?
    };
    write_all_atomic(path, &bytes, true)?;
    Ok(())
}
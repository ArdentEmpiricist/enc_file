//! Key map management for named symmetric keys.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use secrecy::SecretString;

use crate::types::{KeyMap, EncryptOptions, EncFileError};
use crate::crypto::{encrypt_bytes, decrypt_bytes};
use crate::format::write_all_atomic;

/// Load a key map using a password.
pub fn load_keymap(path: &Path, password: SecretString) -> Result<KeyMap, EncFileError> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let pt = decrypt_bytes(&data, password)?;
    let map: KeyMap = serde_cbor::from_slice(&pt)?;
    Ok(map)
}

/// Save a key map using a password (0600 perms on Unix).
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
        encrypt_bytes(&pt, password, opts)?
    };
    write_all_atomic(path, &bytes, true)?;
    Ok(())
}
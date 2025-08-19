//! File I/O operations for encryption and decryption.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use secrecy::SecretString;
use zeroize::Zeroize;

use crate::types::{EncryptOptions, EncFileError};
use crate::crypto::{encrypt_bytes, decrypt_bytes};
use crate::format::write_all_atomic;

/// Encrypt a file on disk using a password-derived key.
///
/// This reads the input file, encrypts it (optionally in streaming mode for large files),
/// and writes the output. The output contains a self-describing header followed by the ciphertext
/// (or ASCII armor if requested).
pub fn encrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    opts: EncryptOptions,
) -> Result<PathBuf, EncFileError> {
    if opts.stream {
        // For now, return an error until we implement streaming module
        return Err(EncFileError::Invalid("streaming not yet implemented in refactored code"));
    }
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    let out_bytes = encrypt_bytes(&data, password, &opts)?;
    let out_path = default_out_path(input, output, "enc");
    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }
    write_all_atomic(&out_path, &out_bytes, false)?;
    Ok(out_path)
}

/// Decrypt a file on disk that was produced by [`encrypt_file`] or [`encrypt_file_streaming`].
pub fn decrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
) -> Result<PathBuf, EncFileError> {
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    let mut pt = decrypt_bytes(&data, password)?;
    let out_path = default_out_path_for_decrypt(input, output);
    if out_path.exists() {
        return Err(EncFileError::Invalid(
            "output exists; use --force (via CLI) to overwrite",
        ));
    }
    write_all_atomic(&out_path, &pt, false)?;
    // Cheap hardening: wipe decrypted plaintext buffer after writing
    pt.zeroize();
    Ok(out_path)
}

fn default_out_path(input: &Path, output: Option<&Path>, ext: &str) -> PathBuf {
    output.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let mut p = input.to_path_buf();
        if let Some(e) = input.extension().and_then(|s| s.to_str()) {
            p.set_extension(format!("{e}.{ext}"));
        } else {
            p.set_extension(ext);
        }
        p
    })
}

fn default_out_path_for_decrypt(input: &Path, output: Option<&Path>) -> PathBuf {
    output.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let s = input.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(".enc") {
            PathBuf::from(stripped)
        } else {
            let mut p = input.to_path_buf();
            p.set_extension("dec");
            p
        }
    })
}

/// Compute a default output path for decryption:
/// - If the input ends with ".enc", strip it.
/// - Otherwise, append ".dec".
pub fn default_decrypt_output_path(in_path: &Path) -> PathBuf {
    let parent = in_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = in_path.file_name().unwrap_or_else(|| OsStr::new("out"));

    // Best-effort UTF-8 handling; fall back to appending ".dec" if not UTF-8.
    if let Some(name) = file_name.to_str() {
        if let Some(stripped) = name.strip_suffix(".enc") {
            return parent.join(stripped);
        }
        return parent.join(format!("{name}.dec"));
    }

    // Non-UTF-8 file name: just append ".dec"
    let mut os = file_name.to_os_string();
    os.push(".dec");
    parent.join(os)
}

/// This avoids relying on internal fields of `PathPersistError` (API-stable).
pub fn persist_tempfile_atomic(
    tmp: tempfile::NamedTempFile,
    out: &Path,
    force: bool,
) -> Result<PathBuf, EncFileError> {
    if out.exists() && !force {
        return Err(EncFileError::Invalid("output exists; use --force to overwrite"));
    }
    tmp.persist(out).map_err(|e| EncFileError::Io(e.error))?;
    Ok(out.to_path_buf())
}
//! File I/O operations for encryption and decryption.

use crate::types::EncFileError;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Atomically write data to a file using a temporary file.
///
/// This function ensures atomic writes by creating a temporary file in the same
/// directory as the target, writing data to it, and then atomically renaming
/// it to the target path.
///
/// # Arguments
///
/// * `path` - Target file path
/// * `data` - Data to write
/// * `mode_600` - Whether to set file permissions to 0o600 (Unix only)
///
/// # Errors
///
/// Returns `EncFileError::Io` for I/O failures or `EncFileError::Invalid` for invalid paths.
pub fn write_all_atomic(path: &Path, data: &[u8], mode_600: bool) -> Result<(), EncFileError> {
    let parent = path
        .parent()
        .ok_or(EncFileError::Invalid("output path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    if mode_600 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
        }
    }
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path).map_err(|e| EncFileError::Io(e.error))?;
    Ok(())
}

/// Generate a default output path by adding an extension.
///
/// If an output path is provided, it's used as-is. Otherwise, the extension
/// is added to the input path (preserving existing extensions).
pub fn default_out_path(input: &Path, output: Option<&Path>, ext: &str) -> PathBuf {
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

/// Generate a default output path for decryption.
///
/// If an output path is provided, it's used as-is. Otherwise:
/// - If the input ends with ".enc", that extension is stripped
/// - Otherwise, ".dec" is appended
pub fn default_out_path_for_decrypt(input: &Path, output: Option<&Path>) -> PathBuf {
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

/// Atomically persist a tempfile to the target path, honoring the force overwrite policy.
///
/// This avoids relying on internal fields of `PathPersistError` for API stability.
pub fn persist_tempfile_atomic(
    tmp: tempfile::NamedTempFile,
    out: &Path,
    force: bool,
) -> Result<PathBuf, EncFileError> {
    // Convert into a TempPath so we control the final rename.
    let tmp_path = tmp.into_temp_path();

    // Enforce overwrite policy here.
    if out.exists() {
        if force {
            fs::remove_file(out)?;
        } else {
            return Err(EncFileError::Invalid(
                "output exists; use --force to overwrite",
            ));
        }
    }

    // Atomically move the temp file to the final location.
    tmp_path
        .persist(out)
        .map_err(|e| EncFileError::Io(e.error))?;
    Ok(out.to_path_buf())
}

/// Determine the default output path for decryption operations.
///
/// This is a public utility function that applies the following logic:
/// - If the input file ends with ".enc", strip that extension
/// - Otherwise, append ".dec"
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

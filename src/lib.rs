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

// Module declarations
mod armor;
mod crypto;
mod file;
mod format;
mod hash;
mod kdf;
mod keymap;
mod streaming;
mod types;

// External dependencies
use secrecy::SecretString;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// Re-export public types and constants
pub use types::{
    AeadAlg, DEFAULT_CHUNK_SIZE, EncFileError, EncryptOptions, HashAlg, KdfAlg, KdfParams, KeyMap,
};

// Re-export public functions
// Core encryption/decryption API
pub use armor::looks_armored;
pub use file::default_decrypt_output_path;
pub use hash::{
    hash_bytes, hash_bytes_keyed_blake3, hash_file, hash_file_keyed_blake3, to_hex_lower,
};
pub use keymap::{load_keymap, save_keymap};
pub use streaming::{encrypt_file_streaming, validate_chunk_size_for_streaming};

// Core encryption and decryption functions

/// Encrypt a byte slice using an AEAD cipher with a password-derived key.
///
/// This is the simplest way to encrypt in-memory data. A random salt and nonce are
/// generated, and the result includes a self-describing header with all necessary
/// metadata for decryption.
///
/// # Options via `EncryptOptions`
/// - `alg: AeadAlg` — Cipher choice: `XChaCha20Poly1305` (default) or `Aes256GcmSiv`.
/// - `kdf: KdfAlg` — Password KDF. Currently `Argon2id` (default).
/// - `kdf_params: KdfParams` — Argon2id tuning:
///   - `t_cost` (passes/iterations)
///   - `mem_kib` (memory in KiB)
///   - `parallelism` (lanes/threads)
/// - `armor: bool` — Wrap output in ASCII armor (Base64) suitable for copy/paste.
/// - `force: bool` — Overwrite existing output files (file APIs only; ignored by byte APIs).
/// - `stream: bool` — Use streaming/chunked framing for constant memory (file APIs only).
/// - `chunk_size: usize` — Chunk size in bytes (streaming only).
///
/// **Ignored fields for this function:** `force`, `stream`, `chunk_size`.
pub fn encrypt_bytes(
    plaintext: &[u8],
    password: SecretString,
    opts: &EncryptOptions,
) -> Result<Vec<u8>, EncFileError> {
    if opts.stream {
        return Err(EncFileError::Invalid("use streaming APIs for stream mode"));
    }

    let salt = crypto::generate_salt()?;
    let key = kdf::derive_key_argon2id(&password, opts.kdf_params, &salt)?;
    let nonce = crypto::generate_nonce(opts.alg)?;

    let ciphertext = crypto::aead_encrypt(opts.alg, &key, &nonce, plaintext)?;
    let header = format::DiskHeader::new_nonstream(
        opts.alg,
        opts.kdf,
        opts.kdf_params,
        salt,
        nonce,
        ciphertext.len() as u64,
    );

    let mut header_bytes = Vec::new();
    ciborium::ser::into_writer(&header, &mut header_bytes)?;
    let mut out = Vec::new();
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);

    let mut key_z = key;
    crypto::zeroize_key(&mut key_z);

    if opts.armor {
        Ok(armor::armor_encode(&out))
    } else {
        Ok(out)
    }
}

/// Decrypt a byte slice that was produced by [`encrypt_bytes`].
///
/// The function parses the self-describing header, derives the key using the embedded
/// Argon2id parameters, and verifies the AEAD tag before returning the plaintext.
pub fn decrypt_bytes(input: &[u8], password: SecretString) -> Result<Vec<u8>, EncFileError> {
    // Handle ASCII armor first (tail-recursive on the dearmored bytes)
    if armor::looks_armored(input) {
        let bin = armor::dearmor_decode(input)?;
        return decrypt_bytes(&bin, password);
    }

    // Minimal header preflight
    if input.len() < 4 {
        return Err(EncFileError::Malformed);
    }
    let header_len = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
    if input.len() < 4 + header_len {
        return Err(EncFileError::Malformed);
    }

    let header_bytes = &input[4..4 + header_len];
    let body = &input[4 + header_len..];

    let header: format::DiskHeader = ciborium::de::from_reader(header_bytes)?;

    // Validate header
    if header.magic != *format::MAGIC {
        return Err(EncFileError::Malformed);
    }
    if header.version != format::VERSION {
        return Err(EncFileError::UnsupportedVersion(header.version));
    }

    // Map algorithms
    let aead_alg = match header.aead_alg {
        1 => AeadAlg::XChaCha20Poly1305,
        2 => AeadAlg::Aes256GcmSiv,
        o => return Err(EncFileError::UnsupportedAead(o)),
    };
    let kdf_alg = match header.kdf_alg {
        1 => KdfAlg::Argon2id,
        o => return Err(EncFileError::UnsupportedKdf(o)),
    };
    let _ = kdf_alg; // currently only Argon2id is supported

    // Validate header-declared chunk size early (streaming only)
    if let Some(stream) = &header.stream {
        streaming::validate_chunk_size_for_streaming(stream.chunk_size as usize)?;
    }

    // Derive key
    let key = kdf::derive_key_argon2id(&password, header.kdf_params, &header.salt)?;

    // Streaming: parse frames into a Vec<u8>
    if let Some(stream) = &header.stream {
        let pt = streaming::decrypt_stream_into_vec(aead_alg, &key, stream, body)?;
        let mut key_z = key;
        crypto::zeroize_key(&mut key_z);
        return Ok(pt);
    }

    // Non-streaming: body length must match `ct_len` from header
    if body.len() as u64 != header.ct_len {
        return Err(EncFileError::Malformed);
    }
    let pt = crypto::aead_decrypt(aead_alg, &key, &header.nonce, body)?;
    let mut key_z = key;
    crypto::zeroize_key(&mut key_z);
    Ok(pt)
}

/// Encrypt a file on disk using the specified options.
///
/// For large files, consider using [`encrypt_file_streaming`] instead to maintain
/// constant memory usage.
pub fn encrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    opts: EncryptOptions,
) -> Result<std::path::PathBuf, EncFileError> {
    if opts.stream {
        return encrypt_file_streaming(input, output, password, opts);
    }
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    let out_bytes = encrypt_bytes(&data, password, &opts)?;
    // Zeroize input plaintext buffer after encryption
    data.zeroize();
    let out_path = file::default_out_path(input, output, "enc");
    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }
    file::write_all_atomic(&out_path, &out_bytes, false)?;
    Ok(out_path)
}

/// Decrypt a file on disk that was produced by [`encrypt_file`] or [`encrypt_file_streaming`].
pub fn decrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
) -> Result<std::path::PathBuf, EncFileError> {
    let out_path = file::default_out_path_for_decrypt(input, output);
    if out_path.exists() {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }

    let mut input_file = File::open(input)?;
    
    // Read a small buffer to check if the file is armored
    let mut peek_buffer = [0u8; 1024];
    let peek_len = input_file.read(&mut peek_buffer)?;
    let peek_data = &peek_buffer[..peek_len];
    
    // If armored, we need to read the entire file to decode it
    if armor::looks_armored(peek_data) {
        // Reset file position and read everything for armor decoding
        input_file.rewind()?;
        let mut file_data = Vec::new();
        input_file.read_to_end(&mut file_data)?;
        let binary_data = armor::dearmor_decode(&file_data)?;
        
        // Process the decoded binary data in memory
        return decrypt_file_from_binary_data(&binary_data, &out_path, password);
    }
    
    // For binary files, we can be more memory-efficient
    // Reset to beginning and parse header without reading entire file
    input_file.rewind()?;
    
    // Read header length
    let mut header_len_buf = [0u8; 4];
    input_file.read_exact(&mut header_len_buf)?;
    let header_len = u32::from_le_bytes(header_len_buf) as usize;
    
    // Read header
    let mut header_buf = vec![0u8; header_len];
    input_file.read_exact(&mut header_buf)?;
    
    let header: format::DiskHeader = ciborium::de::from_reader(&header_buf[..])?;
    
    // Validate format version
    if header.version != format::VERSION {
        return Err(EncFileError::UnsupportedVersion(header.version));
    }

    // Parse algorithms
    let aead_alg = match header.aead_alg {
        1 => types::AeadAlg::XChaCha20Poly1305,
        2 => types::AeadAlg::Aes256GcmSiv,
        o => return Err(EncFileError::UnsupportedAead(o)),
    };

    let kdf_alg = match header.kdf_alg {
        1 => types::KdfAlg::Argon2id,
        o => return Err(EncFileError::UnsupportedKdf(o)),
    };
    let _ = kdf_alg; // currently only Argon2id is supported

    // Derive key
    let key = kdf::derive_key_argon2id(&password, header.kdf_params, &header.salt)?;

    if let Some(stream_info) = &header.stream {
        // Streaming mode: use constant-memory streaming decryption directly from file
        streaming::validate_chunk_size_for_streaming(stream_info.chunk_size as usize)?;
        
        let mut out_file = File::create(&out_path)?;
        
        streaming::decrypt_stream_to_writer(
            &mut input_file,
            &mut out_file,
            aead_alg,
            &key,
            stream_info,
        )?;

        out_file.sync_all()?;

        // Zeroize derived key
        let mut key_z = key;
        crypto::zeroize_key(&mut key_z);

        Ok(out_path)
    } else {
        // Non-streaming mode: read the body into memory
        let expected_body_len = header.ct_len as usize;
        let mut body = vec![0u8; expected_body_len];
        input_file.read_exact(&mut body)?;

        let mut pt = crypto::aead_decrypt(aead_alg, &key, &header.nonce, &body)?;
        file::write_all_atomic(&out_path, &pt, false)?;

        // Cheap hardening: wipe decrypted plaintext buffer after writing
        pt.zeroize();

        // Zeroize derived key
        let mut key_z = key;
        crypto::zeroize_key(&mut key_z);

        Ok(out_path)
    }
}

/// Helper function to decrypt from binary data in memory (used for armored files).
fn decrypt_file_from_binary_data(
    binary_data: &[u8],
    out_path: &Path,
    password: SecretString,
) -> Result<PathBuf, EncFileError> {
    // Now we have binary data, proceed with normal decryption logic
    if binary_data.len() < 4 {
        return Err(EncFileError::Malformed);
    }

    let header_len = u32::from_le_bytes(binary_data[0..4].try_into().unwrap()) as usize;
    if binary_data.len() < 4 + header_len {
        return Err(EncFileError::Malformed);
    }

    let header_buf = &binary_data[4..4 + header_len];

    let header: format::DiskHeader = ciborium::de::from_reader(header_buf)?;

    // Validate format version
    if header.version != format::VERSION {
        return Err(EncFileError::UnsupportedVersion(header.version));
    }

    // Parse algorithms
    let aead_alg = match header.aead_alg {
        1 => types::AeadAlg::XChaCha20Poly1305,
        2 => types::AeadAlg::Aes256GcmSiv,
        o => return Err(EncFileError::UnsupportedAead(o)),
    };

    let kdf_alg = match header.kdf_alg {
        1 => types::KdfAlg::Argon2id,
        o => return Err(EncFileError::UnsupportedKdf(o)),
    };
    let _ = kdf_alg; // currently only Argon2id is supported

    // Derive key
    let key = kdf::derive_key_argon2id(&password, header.kdf_params, &header.salt)?;

    let body = &binary_data[4 + header_len..];

    if let Some(stream_info) = &header.stream {
        // Streaming mode: use constant-memory streaming decryption
        streaming::validate_chunk_size_for_streaming(stream_info.chunk_size as usize)?;

        // For streaming with armored data, we need to create a cursor from the body data
        use std::io::Cursor;
        let mut reader = Cursor::new(body);
        let mut out_file = File::create(out_path)?;

        streaming::decrypt_stream_to_writer(
            &mut reader,
            &mut out_file,
            aead_alg,
            &key,
            stream_info,
        )?;

        out_file.sync_all()?;

        // Zeroize derived key
        let mut key_z = key;
        crypto::zeroize_key(&mut key_z);

        Ok(out_path.to_path_buf())
    } else {
        // Non-streaming mode: decrypt the body directly

        // Body length must match `ct_len` from header
        if body.len() as u64 != header.ct_len {
            return Err(EncFileError::Malformed);
        }

        let mut pt = crypto::aead_decrypt(aead_alg, &key, &header.nonce, body)?;
        file::write_all_atomic(out_path, &pt, false)?;

        // Cheap hardening: wipe decrypted plaintext buffer after writing
        pt.zeroize();

        // Zeroize derived key
        let mut key_z = key;
        crypto::zeroize_key(&mut key_z);

        Ok(out_path.to_path_buf())
    }
}

/// Decrypt options for file operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecryptOptions {
    /// Allow overwriting an existing output file.
    pub force: bool,
}

// Helper to maintain API compatibility
pub fn persist_tempfile_atomic(
    tmp: tempfile::NamedTempFile,
    out: &Path,
    force: bool,
) -> Result<std::path::PathBuf, EncFileError> {
    file::persist_tempfile_atomic(tmp, out, force)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn round_trip_small_default() {
        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions::default();

        let ct = encrypt_bytes(b"abc", pw.clone(), &opts).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, b"abc");
    }

    #[test]
    fn wrong_password_fails() {
        let pw1 = SecretString::new("pw1".into());
        let pw2 = SecretString::new("pw2".into());
        let opts = EncryptOptions::default();

        let ct = encrypt_bytes(b"abc", pw1, &opts).unwrap();
        let result = decrypt_bytes(&ct, pw2);
        assert!(result.is_err());
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

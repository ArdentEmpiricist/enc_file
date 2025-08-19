//! Streaming encryption and decryption for large files.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use getrandom::fill as getrandom;
use secrecy::SecretString;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

use crate::types::{AeadAlg, EncryptOptions, EncFileError, DEFAULT_CHUNK_SIZE};
use crate::format::{DiskHeader, StreamInfo};
use crate::kdf::derive_key_argon2id;
use crate::crypto::AEAD_TAG_LEN;

/// Frame flags: bit0 set => last chunk.
const FLAG_FINAL: u8 = 1;

/// Return an effective chunk size for streaming:
/// - if user passed 0, return DEFAULT_CHUNK_SIZE
/// - if user passed > (u32::MAX - TAG), reject (frame length is a u32 of *ciphertext* bytes)
fn effective_stream_chunk_size(user: usize) -> Result<usize, EncFileError> {
    // Treat 0 as "use default".
    if user == 0 {
        return Ok(DEFAULT_CHUNK_SIZE);
    }

    // Max plaintext per frame so that (pt + TAG) fits in u32.
    let max_pt = (u32::MAX as usize).saturating_sub(AEAD_TAG_LEN);

    if user > max_pt {
        return Err(EncFileError::Invalid(
            "chunk_size too large for 32-bit frame",
        ));
    }
    Ok(user)
}

/// Validate streaming chunk size against the 32-bit frame length format.
/// Each frame length is a big-endian u32 of *ciphertext* bytes; AEAD adds a 16-byte tag,
/// so the maximum safe plaintext chunk size is (u32::MAX - 16).
pub fn validate_chunk_size_for_streaming(chunk_size: usize) -> Result<(), EncFileError> {
    const TAG_LEN: usize = 16;

    if chunk_size == 0 {
        return Err(EncFileError::Invalid("chunk_size must be > 0"));
    }

    // Compute max plaintext size that still fits into a u32 ciphertext length.
    let max_pt = (u32::MAX as usize).saturating_sub(TAG_LEN);

    if chunk_size > max_pt {
        // Use a static message to satisfy EncFileError::Invalid(&'static str)
        return Err(EncFileError::Invalid(
            "chunk_size too large for 32-bit frame",
        ));
    }

    Ok(())
}

/// Helper: write a single framed chunk.
fn write_frame<W: Write>(mut w: W, ct: &[u8], is_final: bool) -> Result<(), EncFileError> {
    let flags = if is_final { FLAG_FINAL } else { 0 };
    w.write_all(&[flags])?;
    w.write_all(&(ct.len() as u32).to_be_bytes())?;
    w.write_all(ct)?;
    Ok(())
}

/// Default output path generation for file operations.
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

/// Encrypt a file on disk using **streaming/chunked framing** for constant memory usage.
///
/// Armored streaming is not available, the argument will be ignored!
pub fn encrypt_file_streaming(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    mut opts: EncryptOptions,
) -> Result<PathBuf, EncFileError> {
    // Enforce chunk-size policy early (0 => default; too big => error).
    if !opts.stream {
        validate_chunk_size_for_streaming(opts.chunk_size)?;
        opts.stream = true;
    }
    let eff_chunk_size = effective_stream_chunk_size(opts.chunk_size)?;
    let out_path = default_out_path(input, output, "enc");

    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }

    // Derive key & build header
    let mut salt = vec![0u8; 16];
    getrandom(&mut salt).map_err(|_| EncFileError::Crypto)?;
    let key = derive_key_argon2id(&password, opts.kdf_params, &salt)?;

    // Prepare stream info
    let stream_info = match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            let mut prefix = vec![0u8; 19];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: eff_chunk_size as u32,
                nonce_prefix: prefix,
            }
        }
        AeadAlg::Aes256GcmSiv => {
            let mut prefix = vec![0u8; 8];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: eff_chunk_size as u32,
                nonce_prefix: prefix,
            }
        }
    };

    let header = DiskHeader::new_stream(
        opts.alg,
        opts.kdf,
        opts.kdf_params,
        salt,
        stream_info.clone(),
    );
    let header_bytes = serde_cbor::to_vec(&header)?;

    // Write header then stream frames
    let parent = out_path.parent().unwrap();
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    tmp.write_all(&header_bytes)?;

    // Input/output streaming
    let mut infile = File::open(input)?;
    let mut buf = vec![0u8; eff_chunk_size];

    match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            use chacha20poly1305::{XChaCha20Poly1305, aead::KeyInit};
            use chacha20poly1305::aead::generic_array::{GenericArray, typenum::U19};
            use chacha20poly1305::aead::stream::EncryptorBE32;

            let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| EncFileError::Crypto)?;
            let prefix = GenericArray::<u8, U19>::from_slice(&stream_info.nonce_prefix);
            let mut encryptor = EncryptorBE32::from_aead(cipher, prefix);

            loop {
                let n = infile.read(&mut buf)?;
                let is_final = n == 0 || n < eff_chunk_size;
                let pt = &buf[..n];

                let ct = if is_final {
                    if n == 0 {
                        break; // EOF without any data
                    }
                    let ct_final = encryptor.encrypt_last(pt).map_err(|_| EncFileError::Crypto)?;
                    write_frame(&mut tmp, &ct_final, is_final)?;
                    break;
                } else {
                    encryptor.encrypt_next(pt).map_err(|_| EncFileError::Crypto)?
                };

                write_frame(&mut tmp, &ct, is_final)?;
            }
            
            // Wipe the whole buffer (covers any leftover bytes from the last read)
            buf.zeroize();
        }

        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::{Aes256GcmSiv, aead::KeyInit, aead::Aead};
            use aes_gcm_siv::aead::generic_array::GenericArray;
            
            let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| EncFileError::Crypto)?;
            // Counter will be appended to 8-byte prefix => 12-byte nonce.
            let prefix = &stream_info.nonce_prefix;
            let mut counter: u32 = 0;
            
            loop {
                let n = infile.read(&mut buf)?;
                let is_final = n == 0 || n < eff_chunk_size;
                let pt = &buf[..n];
                
                if n == 0 {
                    break; // EOF
                }
                
                // nonce = prefix (8 bytes) || counter_be (4 bytes)
                let mut nonce = [0u8; 12];
                nonce[..8].copy_from_slice(prefix);
                nonce[8..].copy_from_slice(&counter.to_be_bytes());
                let nonce_ga = GenericArray::from_slice(&nonce);

                let ct = cipher.encrypt(nonce_ga, pt).map_err(|_| EncFileError::Crypto)?;
                write_frame(&mut tmp, &ct, is_final)?;
                
                counter += 1;
                
                if is_final {
                    break;
                }
            }
            
            // Wipe the whole buffer
            buf.zeroize();
        }
    }

    tmp.flush()?;
    tmp.as_file_mut().sync_all()?;
    
    // Atomically rename the temp file
    let out_path_final = crate::file::persist_tempfile_atomic(tmp, &out_path, opts.force)?;
    
    // Zero the key
    let mut key_z = key;
    key_z.zeroize();
    
    Ok(out_path_final)
}
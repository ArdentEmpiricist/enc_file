//! Streaming encryption and decryption for large files.
//!
//! This module provides constant-memory streaming encryption/decryption
//! using chunked framing. It supports both XChaCha20-Poly1305 and AES-256-GCM-SIV.

use crate::crypto::{
    AEAD_TAG_LEN, create_aes256gcmsiv_cipher, create_xchacha20poly1305_cipher, generate_salt,
};
use crate::file::default_out_path;
use crate::format::{DiskHeader, StreamInfo};
use crate::kdf::derive_key_argon2id;
use crate::types::{AeadAlg, EncFileError, EncryptOptions};
use aead::Aead;
use chacha20poly1305::aead::generic_array::{GenericArray, typenum::U19};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use getrandom::fill as getrandom;
use secrecy::SecretString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

/// Frame flags for streaming format.
const FLAG_FINAL: u8 = 1;

/// Validate streaming chunk size against the 32-bit frame length format.
///
/// We require chunk sizes to leave room for the AEAD tag without overflowing
/// the 32-bit frame length field.
pub fn validate_chunk_size_for_streaming(chunk_size: usize) -> Result<(), EncFileError> {
    if chunk_size == 0 {
        // Standardized message used across encryption/decryption paths
        return Err(EncFileError::Invalid("chunk_size must be > 0"));
    }

    // Leave room for AEAD tag without overflow in the 32-bit ciphertext length field.
    let max_frame_size = (u32::MAX as usize).saturating_sub(AEAD_TAG_LEN);
    if chunk_size > max_frame_size {
        // Standardized message to indicate 32-bit framing limit
        return Err(EncFileError::Invalid(
            "chunk_size too large for 32-bit frame",
        ));
    }

    Ok(())
}

/// Calculate effective streaming chunk size (0 maps to default).
fn effective_stream_chunk_size(user: usize) -> Result<usize, EncFileError> {
    let eff = if user == 0 {
        crate::types::DEFAULT_CHUNK_SIZE
    } else {
        user
    };
    validate_chunk_size_for_streaming(eff)?;
    Ok(eff)
}

/// Validate chunk size from header during decryption.
/// Keep behavior/messages consistent with streaming validator.
fn validate_header_chunk_size(chunk_size: usize) -> Result<(), EncFileError> {
    validate_chunk_size_for_streaming(chunk_size)
}

/// Write a streaming frame with format: [u8 flags][u32 ct_len_be][ct_bytes]
fn write_frame<W: Write>(mut w: W, ct: &[u8], is_final: bool) -> Result<(), EncFileError> {
    let flags = if is_final { FLAG_FINAL } else { 0 };
    w.write_all(&[flags])?;
    w.write_all(&(ct.len() as u32).to_be_bytes())?;
    w.write_all(ct)?;
    Ok(())
}

/// Encrypt a file using streaming/chunked framing for constant memory usage.
///
/// This function processes large files in chunks to maintain constant memory usage.
/// Armored streaming is not supported - the armor flag will be ignored.
pub fn encrypt_file_streaming(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    mut opts: EncryptOptions,
) -> Result<PathBuf, EncFileError> {
    // Enforce chunk-size policy early (0 => default; too big => error)
    if opts.chunk_size == 0 {
        opts.chunk_size = crate::types::DEFAULT_CHUNK_SIZE;
    }
    let eff_chunk_size = effective_stream_chunk_size(opts.chunk_size)?;

    // Force streaming mode
    if !opts.stream {
        opts.stream = true;
    }

    let out_path = default_out_path(input, output, "enc");

    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }

    // Derive key & build header
    let salt = generate_salt()?;
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
            // 8-byte prefix + 32-bit counter per chunk => unique nonces.
            let mut prefix = vec![0u8; 8];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: eff_chunk_size as u32,
                nonce_prefix: prefix,
            }
        }
    };

    let header = DiskHeader::new_stream(opts.alg, opts.kdf, opts.kdf_params, salt, stream_info);
    let header_bytes = serde_cbor::to_vec(&header)?;

    // Streaming: write header + encrypt input file chunk by chunk
    let tmp = NamedTempFile::new_in(
        out_path
            .parent()
            .ok_or(EncFileError::Invalid("output path has no parent"))?,
    )?;
    let mut writer = tmp;

    // Write header
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    // Stream encryption
    let mut reader = File::open(input)?;
    let mut buf = vec![0u8; eff_chunk_size];

    match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher = create_xchacha20poly1305_cipher(&key)?;
            let stream_info = match &header.stream {
                Some(s) => s,
                None => return Err(EncFileError::Invalid("missing stream info")),
            };
            let nonce_prefix = GenericArray::<u8, U19>::from_slice(&stream_info.nonce_prefix);
            let mut enc = EncryptorBE32::from_aead(cipher, nonce_prefix);

            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }

                let pt = &buf[..n];
                let ct = enc.encrypt_next(pt).map_err(|_| EncFileError::Crypto)?;
                write_frame(&mut writer, &ct, false)?;

                // Cheap hardening: wipe the plaintext we just processed
                buf[..n].zeroize();
            }

            // Emit a final empty frame (encrypt_last consumes the encryptor)
            let ct_final = enc
                .encrypt_last(&[] as &[u8])
                .map_err(|_| EncFileError::Crypto)?;
            write_frame(&mut writer, &ct_final, true)?;

            // Wipe the whole buffer (covers any leftover bytes from the last read)
            buf.zeroize();
        }

        AeadAlg::Aes256GcmSiv => {
            let cipher = create_aes256gcmsiv_cipher(&key)?;
            let stream = match header.stream.as_ref() {
                Some(s) => s,
                None => return Err(EncFileError::Invalid("missing stream info")),
            };
            let prefix = &stream.nonce_prefix;
            let mut counter = 0u32;

            loop {
                let n = reader.read(&mut buf)?;
                // Mark final on EOF OR on a short read (< chunk size)
                let is_final = n == 0 || n < eff_chunk_size;

                // If we are at the last available counter and there's more data, we'd overflow.
                if counter == u32::MAX && !is_final {
                    return Err(EncFileError::Invalid("too many frames for 32-bit counter"));
                }

                // Build 12-byte nonce = 8-byte prefix || 4-byte BE counter
                let mut nonce_bytes = prefix.clone();
                nonce_bytes.extend_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);

                // Encrypt this chunk (n may be 0 for the final empty frame)
                let pt = &buf[..n];
                let ct = cipher
                    .encrypt(GenericArray::from_slice(&nonce_bytes), pt)
                    .map_err(|_| EncFileError::Crypto)?;
                write_frame(&mut writer, &ct, is_final)?;

                // Wipe sensitive material
                if n > 0 {
                    buf[..n].zeroize();
                }
                nonce_bytes.zeroize();

                if is_final {
                    break;
                }
            }
            buf.zeroize();
        }
    }

    writer.as_file_mut().flush()?;
    writer.as_file_mut().sync_all()?;
    writer
        .persist(&out_path)
        .map_err(|e| EncFileError::Io(e.error))?;

    // Zeroize derived key
    let mut key_z = key;
    key_z.zeroize();

    Ok(out_path)
}

/// Decrypt streaming data into a Vec<u8>.
///
/// This function reads streaming frames and decrypts them into a continuous buffer.
pub fn decrypt_stream_into_vec(
    alg: AeadAlg,
    key: &[u8; 32],
    stream: &StreamInfo,
    mut body: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    // Validate header-declared chunk size early, using unified policy
    validate_header_chunk_size(stream.chunk_size as usize)?;

    let mut out = Vec::new();

    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher = create_xchacha20poly1305_cipher(key)?;
            if stream.nonce_prefix.len() != 19 {
                return Err(EncFileError::Malformed);
            }
            let nonce_prefix = GenericArray::<u8, U19>::from_slice(&stream.nonce_prefix);
            let mut dec = DecryptorBE32::from_aead(cipher, nonce_prefix);

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                if body.len() < 5 {
                    return Err(EncFileError::Malformed);
                }

                let flags = body[0];
                let ct_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
                body = &body[5..];

                if body.len() < ct_len {
                    return Err(EncFileError::Malformed);
                }

                let ct = &body[..ct_len];
                body = &body[ct_len..];

                let is_final = (flags & FLAG_FINAL) != 0;

                if is_final {
                    let pt = dec.decrypt_last(ct).map_err(|_| EncFileError::Crypto)?;
                    out.extend_from_slice(&pt);
                    break;
                } else {
                    let pt = dec.decrypt_next(ct).map_err(|_| EncFileError::Crypto)?;
                    out.extend_from_slice(&pt);
                }
            }
        }

        AeadAlg::Aes256GcmSiv => {
            let cipher = create_aes256gcmsiv_cipher(key)?;
            let prefix = &stream.nonce_prefix;

            // Ensure AES-GCM-SIV nonce prefix is exactly 8 bytes
            if prefix.len() != 8 {
                return Err(EncFileError::Malformed);
            }

            let mut counter = 0u32;

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                if body.len() < 5 {
                    return Err(EncFileError::Malformed);
                }

                let flags = body[0];
                let ct_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
                body = &body[5..];

                if body.len() < ct_len {
                    return Err(EncFileError::Malformed);
                }

                let ct = &body[..ct_len];
                body = &body[ct_len..];

                let is_final = (flags & FLAG_FINAL) != 0;

                // Reconstruct nonce
                let mut nonce_bytes = prefix.clone();
                nonce_bytes.extend_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);

                let pt = cipher
                    .decrypt(GenericArray::from_slice(&nonce_bytes), ct)
                    .map_err(|_| EncFileError::Crypto)?;
                out.extend_from_slice(&pt);

                // Optional hardening (cheap): wipe nonce bytes
                nonce_bytes.zeroize();

                if is_final {
                    break;
                }
            }
        }
    }

    Ok(out)
}

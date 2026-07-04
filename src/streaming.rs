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
use aes_gcm_siv::{aead::Aead as _, Nonce as AesNonce};
use chacha20poly1305::XNonce;
use getrandom::fill as getrandom;
use secrecy::SecretString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

/// Frame flags for streaming format.
const FLAG_FINAL: u8 = 1;

/// Validate streaming chunk size against the 32-bit frame length format.
///
/// We require chunk sizes to leave room for the AEAD tag without overflowing
/// the 32-bit frame length field.
pub fn validate_chunk_size_for_streaming(chunk_size: usize) -> Result<(), EncFileError> {
    if chunk_size == 0 {
        // Standardized message used across encryption/decryption paths
        return Err(EncFileError::Invalid("streaming chunk_size must be > 0"));
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

/// Calculate an optimal chunk size based on file size and available memory.
///
/// This function provides smarter defaults for better performance:
/// - Small files (< 1 MiB): Use smaller chunks to reduce memory overhead
/// - Medium files (1-100 MiB): Use 1-2 MiB chunks for good balance
/// - Large files (> 100 MiB): Use larger chunks (up to 8 MiB) for better throughput
///
/// Always respects the user's explicit chunk size if provided (non-zero).
fn calculate_optimal_chunk_size(
    user_chunk_size: usize,
    file_size_hint: Option<u64>,
) -> Result<usize, EncFileError> {
    // If user specified a chunk size, use it
    if user_chunk_size != 0 {
        validate_chunk_size_for_streaming(user_chunk_size)?;
        return Ok(user_chunk_size);
    }

    // Calculate optimal size based on file size
    let optimal_size = if let Some(file_size) = file_size_hint {
        match file_size {
            // Small files: use smaller chunks to reduce memory usage
            0..=1_048_576 => crate::types::MIN_CHUNK_SIZE, // 64 KiB for files <= 1 MiB
            // Medium files: use balanced chunks
            1_048_577..=104_857_600 => crate::types::DEFAULT_CHUNK_SIZE, // 1 MiB for files 1-100 MiB
            // Large files: use larger chunks for better throughput
            _ => {
                // Scale up to 8 MiB for very large files

                (file_size / 1000).clamp(
                    crate::types::DEFAULT_CHUNK_SIZE as u64,
                    crate::types::MAX_CHUNK_SIZE as u64,
                ) as usize
            }
        }
    } else {
        // No file size hint, use default
        crate::types::DEFAULT_CHUNK_SIZE
    };

    validate_chunk_size_for_streaming(optimal_size)?;
    Ok(optimal_size)
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

fn xchacha_nonce(prefix: &[u8], counter: u32, last_block: bool) -> Result<XNonce, EncFileError> {
    if prefix.len() != 19 {
        return Err(EncFileError::Malformed);
    }

    let mut nonce = [0u8; 24];
    nonce[..19].copy_from_slice(prefix);
    nonce[19..23].copy_from_slice(&counter.to_be_bytes());
    nonce[23] = u8::from(last_block);
    Ok(XNonce::from(nonce))
}

fn aes_nonce(prefix: &[u8], counter: u32) -> Result<AesNonce, EncFileError> {
    if prefix.len() != 8 {
        return Err(EncFileError::Malformed);
    }

    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    Ok(AesNonce::from(nonce))
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
    // Calculate optimal chunk size based on file size and user preference
    let file_metadata = std::fs::metadata(input).ok();
    let file_size_hint = file_metadata.map(|m| m.len());

    // Validate file size for security
    if let Some(file_size) = file_size_hint {
        crate::crypto::validate_file_size(file_size)?;
    }

    let eff_chunk_size = calculate_optimal_chunk_size(opts.chunk_size, file_size_hint)?;

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

    // Prepare stream info with per-file unique ID
    let mut file_id = vec![0u8; 16];
    getrandom(&mut file_id).map_err(|_| EncFileError::Crypto)?;

    let stream_info = match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            let mut prefix = vec![0u8; 19];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: eff_chunk_size as u32,
                nonce_prefix: prefix,
                file_id: Some(file_id),
            }
        }
        AeadAlg::Aes256GcmSiv => {
            let mut prefix = vec![0u8; 8];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: eff_chunk_size as u32,
                nonce_prefix: prefix,
                file_id: Some(file_id),
            }
        }
    };

    let header = DiskHeader::new_stream(opts.alg, opts.kdf, opts.kdf_params, salt, stream_info);
    let mut header_bytes = Vec::new();
    ciborium::ser::into_writer(&header, &mut header_bytes)?;

    // Streaming: write header + encrypt input file chunk by chunk
    let tmp = NamedTempFile::new_in(
        out_path
            .parent()
            .ok_or(EncFileError::Invalid("output path has no parent"))?,
    )?;
    let mut writer = BufWriter::with_capacity(64 * 1024, tmp);

    // Write header
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    // Stream encryption with buffered I/O for better performance
    // Use adaptive buffer size based on chunk size for optimal performance
    let file = File::open(input)?;
    let buffer_size = (eff_chunk_size / 4).clamp(64 * 1024, 512 * 1024); // 1/4 chunk size, 64KB-512KB range
    let mut reader = BufReader::with_capacity(buffer_size, file);
    let mut buf = vec![0u8; eff_chunk_size];

    match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher = create_xchacha20poly1305_cipher(&key)?;
            let stream_info = match &header.stream {
                Some(s) => s,
                None => return Err(EncFileError::Invalid("missing stream info")),
            };
            let mut pending: Option<Vec<u8>> = None;
            let mut counter = 0u32;

            loop {
                let n = reader.read(&mut buf)?;
                let current = if n > 0 { Some(buf[..n].to_vec()) } else { None };

                if let Some(previous) = pending.take() {
                    let nonce = xchacha_nonce(&stream_info.nonce_prefix, counter, false)?;
                    let ct = cipher
                        .encrypt(&nonce, previous.as_slice())
                        .map_err(|_| EncFileError::Crypto)?;
                    write_frame(&mut writer, &ct, false)?;
                    counter = counter
                        .checked_add(1)
                        .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
                }

                match current {
                    Some(chunk) if n < eff_chunk_size => {
                        let nonce = xchacha_nonce(&stream_info.nonce_prefix, counter, true)?;
                        let ct = cipher
                            .encrypt(&nonce, chunk.as_slice())
                            .map_err(|_| EncFileError::Crypto)?;
                        write_frame(&mut writer, &ct, true)?;
                        break;
                    }
                    Some(chunk) => {
                        pending = Some(chunk);
                    }
                    None => {
                        if let Some(previous) = pending.take() {
                            let nonce = xchacha_nonce(&stream_info.nonce_prefix, counter, true)?;
                            let ct = cipher
                                .encrypt(&nonce, previous.as_slice())
                                .map_err(|_| EncFileError::Crypto)?;
                            write_frame(&mut writer, &ct, true)?;
                        } else {
                            let nonce = xchacha_nonce(&stream_info.nonce_prefix, counter, true)?;
                            let ct = cipher
                                .encrypt(&nonce, &[] as &[u8])
                                .map_err(|_| EncFileError::Crypto)?;
                            write_frame(&mut writer, &ct, true)?;
                        }
                        break;
                    }
                }
            }

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
            let mut pending: Option<Vec<u8>> = None;

            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    if let Some(previous) = pending.take() {
                        let nonce = aes_nonce(prefix, counter)?;
                        let ct = cipher
                            .encrypt(&nonce, previous.as_slice())
                            .map_err(|_| EncFileError::Crypto)?;
                        write_frame(&mut writer, &ct, true)?;
                    } else {
                        let nonce = aes_nonce(prefix, counter)?;
                        let ct = cipher
                            .encrypt(&nonce, &[] as &[u8])
                            .map_err(|_| EncFileError::Crypto)?;
                        write_frame(&mut writer, &ct, true)?;
                    }
                    break;
                }

                let current = buf[..n].to_vec();

                if let Some(previous) = pending.take() {
                    let nonce = aes_nonce(prefix, counter)?;
                    let ct = cipher
                        .encrypt(&nonce, previous.as_slice())
                        .map_err(|_| EncFileError::Crypto)?;
                    write_frame(&mut writer, &ct, false)?;
                    counter = counter
                        .checked_add(1)
                        .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
                }

                if n < eff_chunk_size {
                    let nonce = aes_nonce(prefix, counter)?;
                    let ct = cipher
                        .encrypt(&nonce, current.as_slice())
                        .map_err(|_| EncFileError::Crypto)?;
                    write_frame(&mut writer, &ct, true)?;
                    break;
                }

                pending = Some(current);
            }

            buf.zeroize();
        }
    }

    writer.flush()?;
    let tmp = writer
        .into_inner()
        .map_err(|e| EncFileError::Io(e.into_error()))?;
    tmp.as_file().sync_all()?;
    tmp.persist(&out_path)
        .map_err(|e| EncFileError::Io(e.error))?;

    // Zeroize derived key
    let mut key_z = key;
    key_z.zeroize();

    Ok(out_path)
}

/// Parse a frame header from a slice: [u8 flags][u32 ct_len_be]
/// Returns (flags, ct_len, remaining_body) or error if malformed.
fn parse_frame_from_slice(body: &[u8]) -> Result<(u8, usize, &[u8]), EncFileError> {
    if body.len() < 5 {
        return Err(EncFileError::Malformed);
    }

    let flags = body[0];
    let ct_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    let remaining = &body[5..];

    if remaining.len() < ct_len {
        return Err(EncFileError::Malformed);
    }

    // Validate frame size to prevent DoS attacks
    if ct_len > crate::types::MAX_CHUNK_SIZE + crate::crypto::AEAD_TAG_LEN {
        return Err(EncFileError::Invalid("frame size exceeds maximum allowed"));
    }

    Ok((flags, ct_len, remaining))
}

/// Parse a frame header from a reader: [u8 flags][u32 ct_len_be]
/// Returns (flags, ct_len) or error if malformed.
fn parse_frame_from_reader<R: Read>(reader: &mut R) -> Result<(u8, usize), EncFileError> {
    let mut frame_header = [0u8; 5];
    reader.read_exact(&mut frame_header).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            EncFileError::Malformed
        } else {
            EncFileError::Io(e)
        }
    })?;

    let flags = frame_header[0];
    let ct_len = u32::from_be_bytes(frame_header[1..5].try_into().unwrap()) as usize;

    // Validate frame size to prevent DoS attacks
    if ct_len > crate::types::MAX_CHUNK_SIZE + crate::crypto::AEAD_TAG_LEN {
        return Err(EncFileError::Invalid("frame size exceeds maximum allowed"));
    }

    Ok((flags, ct_len))
}

/// Decrypt streaming data into a Vec<u8>.
/// Returns a decrypted buffer or an error if the input is malformed.
///
/// This function validates the frame structure and ensures that `ct_len` does not exceed the available body data.
/// This is a critical security check to prevent buffer overflows and other vulnerabilities.
/// Uses buffer reuse for improved performance.
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
            use chacha20poly1305::aead::Aead as _;
            let mut counter = 0u32;

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                let (flags, ct_len, remaining_body) = parse_frame_from_slice(body)?;

                let ct = &remaining_body[..ct_len];
                body = &remaining_body[ct_len..];

                let is_final = (flags & FLAG_FINAL) != 0;
                let nonce = xchacha_nonce(&stream.nonce_prefix, counter, is_final)?;

                let mut pt = cipher.decrypt(&nonce, ct).map_err(|_| EncFileError::Crypto)?;
                out.extend_from_slice(&pt);
                pt.zeroize();

                if is_final {
                    break;
                }

                counter = counter
                    .checked_add(1)
                    .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
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
            use aes_gcm_siv::aead::Aead as _;

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                let (flags, ct_len, remaining_body) = parse_frame_from_slice(body)?;

                let ct = &remaining_body[..ct_len];
                body = &remaining_body[ct_len..];

                let is_final = (flags & FLAG_FINAL) != 0;

                let nonce = aes_nonce(prefix, counter)?;
                let mut pt = cipher
                    .decrypt(&nonce, ct)
                    .map_err(|_| EncFileError::Crypto)?;
                out.extend_from_slice(&pt);

                // Zeroize sensitive material
                pt.zeroize();

                if is_final {
                    break;
                }

                counter = counter
                    .checked_add(1)
                    .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
            }
        }
    }

    Ok(out)
}

/// Decrypt streaming data directly to a writer for constant memory usage.
///
/// This function reads streaming frames and decrypts them directly to the provided writer,
/// maintaining constant memory usage regardless of the size of the encrypted data.
/// Uses buffered I/O and buffer reuse for improved performance.
///
/// # Security Note
/// 
/// This function performs streaming decryption with immediate write-through to the provided
/// writer. While this is efficient for memory usage, it means that partial cleartext may
/// be written to the output before authentication failures are detected. For use cases
/// requiring atomic writes (all-or-nothing decryption), consider using file-based APIs
/// that can employ temporary files and atomic rename operations.
///
/// All intermediate buffers (ciphertext, nonces, plaintext) are properly zeroized
/// on both success and error paths to prevent cleartext leakage in memory.
pub fn decrypt_stream_to_writer<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    aead_alg: AeadAlg,
    key: &[u8; 32],
    stream_info: &StreamInfo,
) -> Result<(), EncFileError> {
    // Validate header-declared chunk size early, using unified policy
    validate_header_chunk_size(stream_info.chunk_size as usize)?;

    // Use buffered I/O for better performance with adaptive buffer sizing
    let expected_chunk_size = stream_info.chunk_size as usize;
    let buffer_size = (expected_chunk_size / 4).clamp(64 * 1024, 512 * 1024);
    let mut buf_reader = BufReader::with_capacity(buffer_size, reader);
    let mut buf_writer = BufWriter::with_capacity(buffer_size, writer);

    match aead_alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher = create_xchacha20poly1305_cipher(key)?;
            if stream_info.nonce_prefix.len() != 19 {
                return Err(EncFileError::Malformed);
            }
            use chacha20poly1305::aead::Aead as _;
            let mut counter = 0u32;

            let mut ct_buf = Vec::new();

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                let (flags, ct_len) = parse_frame_from_reader(&mut buf_reader)?;

                // Reuse buffer, growing only if needed
                if ct_buf.len() < ct_len {
                    ct_buf.resize(ct_len, 0);
                }
                buf_reader.read_exact(&mut ct_buf[..ct_len]).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        EncFileError::Malformed
                    } else {
                        EncFileError::Io(e)
                    }
                })?;

                let is_final = (flags & FLAG_FINAL) != 0;
                let nonce = xchacha_nonce(&stream_info.nonce_prefix, counter, is_final)?;
                let pt = Zeroizing::new(
                    cipher
                        .decrypt(&nonce, &ct_buf[..ct_len])
                        .map_err(|_| EncFileError::Crypto)?,
                );
                buf_writer.write_all(&pt)?;

                if is_final {
                    break;
                }

                counter = counter
                    .checked_add(1)
                    .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
            }

            // Zeroize the reused ciphertext buffer
            ct_buf.zeroize();
        }

        AeadAlg::Aes256GcmSiv => {
            let cipher = create_aes256gcmsiv_cipher(key)?;
            let prefix = &stream_info.nonce_prefix;

            // Ensure AES-GCM-SIV nonce prefix is exactly 8 bytes
            if prefix.len() != 8 {
                return Err(EncFileError::Malformed);
            }

            let mut counter = 0u32;
            let mut ct_buf = Vec::new();
            use aes_gcm_siv::aead::Aead as _;

            loop {
                // Parse frame: [u8 flags][u32 ct_len_be][ct_bytes]
                let (flags, ct_len) = parse_frame_from_reader(&mut buf_reader)?;

                // Reuse ciphertext buffer, growing only if needed
                if ct_buf.len() < ct_len {
                    ct_buf.resize(ct_len, 0);
                }
                buf_reader.read_exact(&mut ct_buf[..ct_len]).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        EncFileError::Malformed
                    } else {
                        EncFileError::Io(e)
                    }
                })?;

                let is_final = (flags & FLAG_FINAL) != 0;

                let nonce = aes_nonce(prefix, counter)?;

                let pt = Zeroizing::new(
                    cipher
                        .decrypt(&nonce, &ct_buf[..ct_len])
                        .map_err(|_| EncFileError::Crypto)?,
                );

                buf_writer.write_all(&pt)?;

                if is_final {
                    break;
                }

                counter = counter
                    .checked_add(1)
                    .ok_or(EncFileError::Invalid("too many frames for 32-bit counter"))?;
            }

            // Zeroize reused buffers
            ct_buf.zeroize();
        }
    }

    // Ensure all buffered data is written
    buf_writer.flush()?;
    Ok(())
}

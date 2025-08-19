//! Core encryption and decryption operations.

use aead::{Aead, KeyInit};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill as getrandom;
use secrecy::SecretString;
use zeroize::Zeroize;

use crate::types::{AeadAlg, KdfAlg, EncryptOptions, EncFileError};
use crate::format::{DiskHeader, MAGIC, VERSION, StreamInfo};
use crate::kdf::derive_key_argon2id;
use crate::armor::{armor_encode, dearmor_decode, looks_armored};

/// AEAD tag length in bytes (Poly1305 and GCM-SIV are 16 bytes).
pub const AEAD_TAG_LEN: usize = 16;

pub fn aead_encrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

pub fn aead_decrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

pub fn nonce_len_for(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::XChaCha20Poly1305 => 24,
        AeadAlg::Aes256GcmSiv => 12,
    }
}

/// Validate a chunk size coming *from the header* during decryption.
/// This defends against malformed/crafted inputs.
pub fn validate_header_chunk_size(chunk_size: usize) -> Result<(), EncFileError> {
    if chunk_size == 0 {
        return Err(EncFileError::Invalid("invalid chunk_size in header"));
    }
    let max_pt = (u32::MAX as usize).saturating_sub(AEAD_TAG_LEN);
    if chunk_size > max_pt {
        return Err(EncFileError::Invalid(
            "chunk_size exceeds 32-bit frame in header",
        ));
    }
    Ok(())
}

/// Decrypt framed ciphertext (in-memory) using the given header stream info.
pub fn decrypt_stream_into_vec(
    alg: AeadAlg,
    key: &[u8; 32],
    stream: &StreamInfo,
    body: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    use std::io::Read;

    let mut reader = std::io::Cursor::new(body);
    let mut out = Vec::new();

    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            use chacha20poly1305::aead::generic_array::{GenericArray, typenum::U19};
            use chacha20poly1305::aead::stream::DecryptorBE32;

            let prefix = GenericArray::<u8, U19>::from_slice(&stream.nonce_prefix);
            let mut decryptor = DecryptorBE32::from_aead(
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?,
                prefix,
            );

            loop {
                let mut flags_buf = [0u8; 1];
                if reader.read_exact(&mut flags_buf).is_err() {
                    break;
                }
                let is_final = flags_buf[0] & 0x01 != 0;

                let mut len_buf = [0u8; 4];
                reader.read_exact(&mut len_buf)?;
                let chunk_len = u32::from_be_bytes(len_buf) as usize;

                let mut ct_chunk = vec![0u8; chunk_len];
                reader.read_exact(&mut ct_chunk)?;

                let pt_chunk = if is_final {
                    let pt_final = decryptor.decrypt_last(ct_chunk.as_slice()).map_err(|_| EncFileError::Crypto)?;
                    out.extend_from_slice(&pt_final);
                    break;
                } else {
                    decryptor.decrypt_next(ct_chunk.as_slice()).map_err(|_| EncFileError::Crypto)?
                };
                out.extend_from_slice(&pt_chunk);

                if is_final {
                    break;
                }
            }
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;

            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let prefix = &stream.nonce_prefix;
            let mut counter: u32 = 0;

            loop {
                let mut flags_buf = [0u8; 1];
                if reader.read_exact(&mut flags_buf).is_err() {
                    break;
                }
                let is_final = flags_buf[0] & 0x01 != 0;

                let mut len_buf = [0u8; 4];
                reader.read_exact(&mut len_buf)?;
                let chunk_len = u32::from_be_bytes(len_buf) as usize;

                let mut ct_chunk = vec![0u8; chunk_len];
                reader.read_exact(&mut ct_chunk)?;

                let mut nonce = [0u8; 12];
                nonce[..8].copy_from_slice(prefix);
                nonce[8..].copy_from_slice(&counter.to_be_bytes());
                let nonce_ga = GenericArray::from_slice(&nonce);

                let pt_chunk = cipher.decrypt(nonce_ga, ct_chunk.as_slice())
                    .map_err(|_| EncFileError::Crypto)?;
                out.extend_from_slice(&pt_chunk);

                counter += 1;

                if is_final {
                    break;
                }
            }
        }
    }

    Ok(out)
}

/// Encrypt a byte slice using an AEAD cipher with a password-derived key.
///
/// This is the simplest way to encrypt in-memory data. A random salt and nonce are
/// generated and encoded into the output so the same inputs never produce the same ciphertext.
pub fn encrypt_bytes(
    plaintext: &[u8],
    password: SecretString,
    opts: &EncryptOptions,
) -> Result<Vec<u8>, EncFileError> {
    if opts.stream {
        return Err(EncFileError::Invalid("use streaming APIs for stream mode"));
    }
    let mut salt = vec![0u8; 16];
    getrandom(&mut salt).map_err(|_| EncFileError::Crypto)?;
    let key = derive_key_argon2id(&password, opts.kdf_params, &salt)?;
    let mut nonce = vec![0u8; nonce_len_for(opts.alg)];
    getrandom(&mut nonce).map_err(|_| EncFileError::Crypto)?;

    let ciphertext = aead_encrypt(opts.alg, &key, &nonce, plaintext)?;
    let header = DiskHeader::new_nonstream(
        opts.alg,
        opts.kdf,
        opts.kdf_params,
        salt,
        nonce,
        ciphertext.len() as u64,
    );
    let header_bytes = serde_cbor::to_vec(&header)?;

    let mut out = Vec::with_capacity(4 + header_bytes.len() + ciphertext.len());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);

    let mut key_z = key;
    key_z.zeroize();

    if opts.armor {
        Ok(armor_encode(&out))
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
    if looks_armored(input) {
        let bin = dearmor_decode(input)?;
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

    // Parse header (CBOR)
    let header: DiskHeader = serde_cbor::from_slice(&input[4..4 + header_len])?;
    if &header.magic != MAGIC {
        return Err(EncFileError::Malformed);
    }
    if header.version != VERSION {
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

    // Validate header-declared chunk size early (streaming only) -------
    if let Some(stream) = &header.stream {
        // Defense-in-depth: reject zero or > u32::MAX - TAG before any heavy work.
        validate_header_chunk_size(stream.chunk_size as usize)?;
    }

    // Derive the key (only after header validation to avoid KDF work on malformed input)
    let key = derive_key_argon2id(&password, header.kdf_params, &header.salt)?;
    let body = &input[4 + header_len..];

    // Streaming: parse frames into a Vec<u8> (your helper does the per-frame work)
    if let Some(stream) = &header.stream {
        let pt = decrypt_stream_into_vec(aead_alg, &key, stream, body)?;
        let mut key_z = key;
        key_z.zeroize();
        return Ok(pt);
    }

    // Non-streaming: body length must match `ct_len` from header
    if body.len() as u64 != header.ct_len {
        return Err(EncFileError::Malformed);
    }
    let pt = aead_decrypt(aead_alg, &key, &header.nonce, body)?;
    let mut key_z = key;
    key_z.zeroize();
    Ok(pt)
}
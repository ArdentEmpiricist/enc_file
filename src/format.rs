//! On-disk file format definitions and constants.

use crate::types::{AeadAlg, KdfAlg, KdfParams};
use serde::{Deserialize, Serialize};

/// File format magic bytes.
pub const MAGIC: &[u8; 8] = b"ENCFILE\0";

/// Current file format version.
pub const VERSION: u16 = 2;

/// Optional streaming info (present when the file is chunk-framed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    /// Chunk size used by the writer.
    pub chunk_size: u32,
    /// Nonce prefix for streaming:
    /// - XChaCha20-Poly1305: 19 bytes (used with EncryptorBE32/DecryptorBE32)
    /// - AES-256-GCM-SIV:    8 bytes (we append a 32-bit big-endian counter)
    pub nonce_prefix: Vec<u8>,
    // For AES-GCM-SIV we increment a 32-bit counter per chunk to build unique nonces.
    // For XChaCha20-Poly1305 the streaming helper manages the counter internally.
}

/// Versioned header (CBOR-encoded). Adding optional fields is forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub aead_alg: u8,
    pub kdf_alg: u8,
    pub kdf_params: KdfParams,
    /// Non-streaming nonce (full length) OR unused when `stream.is_some()`.
    pub nonce: Vec<u8>,
    /// Per-file KDF salt (16 bytes is typical).
    pub salt: Vec<u8>,
    /// Total ciphertext length for non-streaming files (used for validation).
    pub ct_len: u64,
    /// Present when the file is written in streaming mode.
    pub stream: Option<StreamInfo>,
}

impl DiskHeader {
    /// Create a new header for non-streaming encryption.
    pub fn new_nonstream(
        aead_alg: AeadAlg,
        kdf_alg: KdfAlg,
        kdf_params: KdfParams,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        ct_len: u64,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            aead_alg: aead_alg as u8,
            kdf_alg: kdf_alg as u8,
            kdf_params,
            nonce,
            salt,
            ct_len,
            stream: None,
        }
    }

    /// Create a new header for streaming encryption.
    pub fn new_stream(
        aead_alg: AeadAlg,
        kdf_alg: KdfAlg,
        kdf_params: KdfParams,
        salt: Vec<u8>,
        stream: StreamInfo,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            aead_alg: aead_alg as u8,
            kdf_alg: kdf_alg as u8,
            kdf_params,
            nonce: Vec::new(), // unused in streaming mode
            salt,
            ct_len: 0, // not used in streaming mode
            stream: Some(stream),
        }
    }
}
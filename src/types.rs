//! Core types and enums for enc_file.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default chunk size for streaming (1 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;

/// Supported AEAD algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AeadAlg {
    /// XChaCha20-Poly1305 (24-byte nonces). Supports built-in streaming helpers.
    #[default]
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM-SIV (12-byte nonces). We implement simple counter-based streaming.
    Aes256GcmSiv = 2,
}

/// Supported password KDFs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum KdfAlg {
    #[default]
    Argon2id = 1,
}

/// Tunable KDF parameters (mem_kib in KiB).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub t_cost: u32,
    pub mem_kib: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Hardened defaults for security (2024+ recommendations)
        Self {
            t_cost: 3,
            mem_kib: 64 * 1024,
            parallelism: (num_cpus::get() as u32).clamp(1, 4),
        }
    }
}

/// Options for encryption.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub alg: AeadAlg,
    pub kdf: KdfAlg,
    pub kdf_params: KdfParams,
    /// When `true`, wraps the binary file in an ASCII-armored envelope (Base64).
    pub armor: bool,
    /// When `true`, allow overwriting existing output file paths.
    pub force: bool,
    /// Stream in constant memory using chunked framing (recommended for very large files).
    pub stream: bool,
    /// Chunk size in bytes (only applies when `stream == true`).
    pub chunk_size: usize,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            alg: AeadAlg::default(),
            kdf: KdfAlg::default(),
            kdf_params: KdfParams::default(),
            armor: false,
            force: false,
            stream: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl EncryptOptions {
    /// Enable/disable ASCII armor in a Clippy-friendly way.
    pub fn with_armor(mut self, on: bool) -> Self {
        self.armor = on;
        self
    }
}

/// Library error type (no panics for expected failures).
#[derive(Error, Debug)]
pub enum EncFileError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("encryption/decryption failure")]
    Crypto,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported AEAD algorithm id {0}")]
    UnsupportedAead(u8),
    #[error("unsupported KDF algorithm id {0}")]
    UnsupportedKdf(u8),
    #[error("malformed file")]
    Malformed,
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
    #[error("serialization error")]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),
    #[error("serialization error")]  
    CborSer(#[from] ciborium::ser::Error<std::io::Error>),
}

/// Supported hash algorithms for general purpose hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlg {
    /// BLAKE3 (32-byte digest). Default.
    #[default]
    Blake3,
    /// SHA-256 (32-byte digest)
    Sha256,
    /// SHA-512 (64-byte digest)
    Sha512,
    /// SHA3-256 (32-byte digest)
    Sha3_256,
    /// SHA3-512 (64-byte digest)
    Sha3_512,
    /// BLAKE2b (64-byte digest; unkeyed mode here)
    Blake2b,
    /// XXH3 64-bit (8-byte digest; NOT cryptographic — integrity only)
    Xxh3_64,
    /// XXH3 128-bit (16-byte digest; NOT cryptographic — integrity only)
    Xxh3_128,
    /// CRC32 (4-byte checksum; NOT cryptographic — integrity only)
    Crc32,
}

/// Type alias for encrypted key maps.
pub type KeyMap = std::collections::HashMap<String, Vec<u8>>;
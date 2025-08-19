//! Core types and enums for enc_file library.

use std::collections::HashMap;
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
        Self {
            t_cost: 2,
            mem_kib: 64 * 1024,
            parallelism: 1,
        }
    }
}

/// Options for encryption.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub alg: AeadAlg,
    pub armor: bool,
    pub force: bool,
    pub stream: bool,
    pub chunk_size: usize,
    pub kdf: KdfAlg,
    pub kdf_params: KdfParams,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            alg: AeadAlg::default(),
            armor: false,
            force: false,
            stream: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
            kdf: KdfAlg::default(),
            kdf_params: KdfParams::default(),
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

/// Options for decryption.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecryptOptions {
    // Currently no fields, but kept for future extensibility
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
    Serde(#[from] serde_cbor::Error),
}

/// An encrypted key map: name -> raw 32-byte key (opaque).
pub type KeyMap = HashMap<String, Vec<u8>>;
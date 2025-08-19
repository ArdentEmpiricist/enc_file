//! Hashing functionality with support for multiple algorithms.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::types::EncFileError;

/// Common hashing algorithms your library supports.
///
/// Default is `Blake3` for performance and modern security properties.
/// Add or remove variants as needed.
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

/// Hash a byte slice and return the raw digest bytes.
pub fn hash_bytes(data: &[u8], alg: HashAlg) -> Vec<u8> {
    match alg {
        HashAlg::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(data);
            hasher.finalize().as_bytes().to_vec() // 32
        }
        HashAlg::Sha256 => {
            use sha2::{Digest, Sha256};
            Sha256::digest(data).to_vec() // 32
        }
        HashAlg::Sha512 => {
            use sha2::{Digest, Sha512};
            Sha512::digest(data).to_vec() // 64
        }
        HashAlg::Sha3_256 => {
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest(data).to_vec() // 32
        }
        HashAlg::Sha3_512 => {
            use sha3::{Digest, Sha3_512};
            Sha3_512::digest(data).to_vec() // 64
        }
        HashAlg::Blake2b => {
            use blake2::{Blake2b512, Digest};
            Blake2b512::digest(data).to_vec() // 64
        }
        HashAlg::Xxh3_64 => {
            use xxhash_rust::xxh3::xxh3_64;
            xxh3_64(data).to_be_bytes().to_vec() // 8
        }
        HashAlg::Xxh3_128 => {
            use xxhash_rust::xxh3::xxh3_128;
            xxh3_128(data).to_be_bytes().to_vec() // 16
        }
        HashAlg::Crc32 => {
            use crc::{CRC_32_ISO_HDLC, Crc};
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let mut d = crc.digest();
            d.update(data);
            d.finalize().to_be_bytes().to_vec() // 4
        }
    }
}

/// Hash a file (streaming) and return the raw digest bytes.
///
/// Uses a buffered reader and feeds the hasher in chunks.
/// Returns `EncFileError::Io` (assuming you have that) on I/O failures.
pub fn hash_file(path: &Path, alg: HashAlg) -> Result<Vec<u8>, EncFileError> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buf = vec![0u8; 64 * 1024];

    match alg {
        HashAlg::Blake3 => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().as_bytes().to_vec())
        }
        HashAlg::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha512 => {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha3_256 => {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha3_512 => {
            use sha3::{Digest, Sha3_512};
            let mut h = Sha3_512::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Blake2b => {
            use blake2::{Blake2b512, Digest};
            let mut h = Blake2b512::default(); // 64-Byte Output
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Xxh3_64 => {
            use xxhash_rust::xxh3::Xxh3;
            let mut h = Xxh3::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.digest().to_be_bytes().to_vec())
        }

        HashAlg::Xxh3_128 => {
            use xxhash_rust::xxh3::Xxh3;
            let mut h = Xxh3::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.digest128().to_be_bytes().to_vec())
        }
        HashAlg::Crc32 => {
            use crc::{CRC_32_ISO_HDLC, Crc};
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let mut d = crc.digest();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                d.update(&buf[..n]);
            }
            Ok(d.finalize().to_be_bytes().to_vec())
        }
    }
}

/// Keyed BLAKE3 hash (32-byte key). Only for BLAKE3 — other algorithms ignore keys or use HMACs.
///
/// # Safety
/// - This is *not* a KDF. It is a keyed hash for authentication (like a MAC).
/// - `key32` **must** be a 32-byte secret key.
pub fn hash_bytes_keyed_blake3(data: &[u8], key32: &[u8; 32]) -> [u8; 32] {
    blake3::keyed_hash(key32, data).into()
}

/// Keyed BLAKE3 file hash (streaming).
pub fn hash_file_keyed_blake3(path: &Path, key32: &[u8; 32]) -> Result<[u8; 32], EncFileError> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buf = vec![0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new_keyed(key32);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Helper to hex-encode (lower-case) for display or logs.
pub fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
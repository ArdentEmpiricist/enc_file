//! Keyed BLAKE3 integrity tests.
//!
//! We derive a deterministic 32-byte BLAKE3 key from the password (test-only!),
//! compute keyed hashes of plaintext before encryption, then verify that the
//! decrypted bytes match by comparing keyed hashes.
//!
//! This is *test* code — the library does its own AEAD auth. We just add an
//! extra “belt & suspenders” check that round-trips are exact.

use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io::{Read, Write};
use tempfile::tempdir;

use enc_file::{AeadAlg, EncryptOptions, decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file};

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

#[inline]
fn kib(n: usize) -> usize {
    n.saturating_mul(KIB)
}
#[inline]
fn mib(n: usize) -> usize {
    n.saturating_mul(MIB)
}

/// Unkeyed BLAKE3 helper that returns a fixed [u8; 32] for ergonomic asserts.
fn blake3_32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hash = blake3::hash(data);
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Derive a BLAKE3 key from a password and context string (test-only).
/// Uses BLAKE3's built-in KDF (derive_key) to create a 32-byte key.
fn blake3_key_from_pw(context: &str, pw: &SecretString) -> [u8; 32] {
    blake3::derive_key(context, pw.expose_secret().as_bytes())
}

/// Compute keyed BLAKE3 and return [u8; 32] for easy equality checks.
fn blake3_32_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hash = blake3::keyed_hash(key, data);
    out.copy_from_slice(hash.as_bytes());
    out
}

#[test]
fn keyed_hash_roundtrip_bytes_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        // Deterministic payload of ~1 MiB + 3 KiB
        let msg = {
            let mut v = vec![0u8; mib(1) + kib(3)];
            for (i, b) in v.iter_mut().enumerate() {
                // A simple deterministic pattern (cheap linear-congruential-like).
                *b = (i as u32).wrapping_mul(2246822519).wrapping_add(3266489917) as u8;
            }
            v
        };

        let pw = SecretString::new(format!("keyed-hash-bytes-{alg:?}").into_boxed_str());

        let key = blake3_key_from_pw("enc_file/tests/keyed_hash_bytes", &pw);

        let expected_keyed = blake3_32_keyed(&key, &msg);

        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        let ct = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();
        let round = decrypt_bytes(&ct, pw).unwrap();

        let got_keyed = blake3_32_keyed(&key, &round);
        assert_eq!(
            got_keyed, expected_keyed,
            "keyed blake3 mismatch: alg={:?}",
            alg
        );

        // (Optional) also compare unkeyed as a sanity check
        assert_eq!(
            blake3_32(&round),
            blake3_32(&msg),
            "unkeyed blake3 mismatch: alg={:?}",
            alg
        );
    }
}

#[test]
fn keyed_hash_roundtrip_files_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.enc");
        let back_path = dir.path().join("back.bin");

        // Create ~1 MiB file with deterministic data
        let mut data = vec![0u8; mib(1)];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(2654435761).wrapping_add(1013904223) as u8;
        }
        fs::File::create(&in_path)
            .unwrap()
            .write_all(&data)
            .unwrap();

        let pw = SecretString::new(format!("keyed-hash-bytes-{alg:?}").into_boxed_str());

        let key = blake3_key_from_pw("enc_file/tests/keyed_hash_files", &pw);

        let expected_keyed = blake3_32_keyed(&key, &data);

        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        encrypt_file(&in_path, Some(&enc_path), pw.clone(), opts).unwrap();
        decrypt_file(&enc_path, Some(&back_path), pw).unwrap();

        let mut round = Vec::new();
        fs::File::open(&back_path)
            .unwrap()
            .read_to_end(&mut round)
            .unwrap();

        let got_keyed = blake3_32_keyed(&key, &round);
        assert_eq!(
            got_keyed, expected_keyed,
            "keyed blake3 mismatch: alg={:?}",
            alg
        );

        // (Optional) also compare unkeyed as a sanity check
        assert_eq!(
            blake3_32(&round),
            blake3_32(&data),
            "unkeyed blake3 mismatch: alg={:?}",
            alg
        );
    }
}

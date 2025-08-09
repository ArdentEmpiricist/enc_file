//! Hashing/integrity tests using BLAKE3.
//!
//! We compute BLAKE3 of the plaintext, run encrypt->decrypt with *both*
//! algorithms, then verify the BLAKE3 of the decrypted output matches.
//! Faster than SHA-256, great for test throughput on large inputs.

use std::fs;
use std::io::{Read, Write};

use enc_file::{decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file, AeadAlg, EncryptOptions};
use secrecy::SecretString;
use tempfile::tempdir;

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

fn blake3_32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hash = blake3::hash(data);
    out.copy_from_slice(hash.as_bytes());
    out
}

#[test]
fn hashing_roundtrip_bytes_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        // Deterministic payload
        let msg = {
            let mut v = vec![0u8; mib(1) + kib(3)];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (i as u32).wrapping_mul(2246822519).wrapping_add(3266489917) as u8;
            }
            v
        };

        let expected = blake3_32(&msg);

        let pw = SecretString::new("hash-test".into());
        let ct = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();
        let round = decrypt_bytes(&ct, pw).unwrap();

        let got = blake3_32(&round);
        assert_eq!(got, expected, "alg={:?}", alg);
    }
}

#[test]
fn hashing_roundtrip_files_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.enc");
        let back_path = dir.path().join("back.bin");

        // Create input file with deterministic data
        let mut data = vec![0u8; mib(1)];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(2654435761).wrapping_add(1013904223) as u8;
        }
        fs::File::create(&in_path)
            .unwrap()
            .write_all(&data)
            .unwrap();

        let expected = blake3_32(&data);

        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        let pw = SecretString::new("hash-file".into());
        encrypt_file(&in_path, Some(&enc_path), pw.clone(), opts).unwrap();
        decrypt_file(&enc_path, Some(&back_path), pw).unwrap();

        let mut round = Vec::new();
        fs::File::open(&back_path)
            .unwrap()
            .read_to_end(&mut round)
            .unwrap();

        let got = blake3_32(&round);
        assert_eq!(got, expected, "alg={:?}", alg);
    }
}

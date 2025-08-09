//! Streaming-focused integration tests that run against *both* algorithms.
//! Uses uniform KiB/MiB helpers.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use enc_file::{decrypt_file, encrypt_file, AeadAlg};
use secrecy::SecretString;
use tempfile::tempdir;

// --- Size helpers (KiB/MiB) ---

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

// --- Local helpers ---

fn write_blob(path: &Path, len: usize) {
    let mut data = vec![0u8; len];
    // Deterministic pseudo-random-ish content (good for repeatable tests)
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(1664525).wrapping_add(1013904223) as u8;
    }
    fs::File::create(path).unwrap().write_all(&data).unwrap();
}

fn slurp(path: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    fs::File::open(path).unwrap().read_to_end(&mut v).unwrap();
    v
}

/// Build streaming encryption options for the given algorithm.
/// Armor and other defaults can be toggled here if desired.
fn streaming_opts(alg: enc_file::AeadAlg) -> enc_file::EncryptOptions {
    enc_file::EncryptOptions {
        alg,
        stream: true,
        armor: false, // change to true if you want ASCII armor in streaming tests
        ..Default::default()
    }
}

#[test]
fn streaming_empty_file_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let enc = dir.path().join("out.enc");
        let back = dir.path().join("back.bin");

        write_blob(&infile, 0);
        let pw = SecretString::new("pw".into());

        encrypt_file(&infile, Some(&enc), pw.clone(), streaming_opts(alg)).unwrap();
        decrypt_file(&enc, Some(&back), pw).unwrap();

        assert_eq!(slurp(&infile), slurp(&back), "alg={:?}", alg);
    }
}

#[test]
fn streaming_boundary_sized_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let enc = dir.path().join("out.enc");
        let back = dir.path().join("back.bin");

        // Size that should exercise final-frame boundaries
        let size = mib(1) + kib(64) + 7;
        write_blob(&infile, size);

        let pw = SecretString::new("pw".into());

        encrypt_file(&infile, Some(&enc), pw.clone(), streaming_opts(alg)).unwrap();
        decrypt_file(&enc, Some(&back), pw).unwrap();

        assert_eq!(slurp(&infile), slurp(&back), "alg={:?}", alg);
    }
}

#[test]
fn streaming_roundtrip_large_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let enc = dir.path().join("out.enc");
        let back = dir.path().join("back.bin");

        write_blob(&infile, mib(2));
        let pw = SecretString::new("pw".into());

        encrypt_file(&infile, Some(&enc), pw.clone(), streaming_opts(alg)).unwrap();
        decrypt_file(&enc, Some(&back), pw).unwrap();

        assert_eq!(slurp(&infile), slurp(&back), "alg={:?}", alg);
    }
}

#[test]
fn streaming_mid_body_tamper_fails_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let enc = dir.path().join("out.enc");
        let back = dir.path().join("back.bin");

        write_blob(&infile, kib(256));
        let pw = SecretString::new("pw".into());

        encrypt_file(&infile, Some(&enc), pw.clone(), streaming_opts(alg)).unwrap();

        // Tamper somewhere in the middle of the ciphertext body
        let mut ct = slurp(&enc);
        let mid = ct.len().saturating_div(2);
        let start = mid.saturating_sub(8);
        let end = (mid + 8).min(ct.len());
        for byte in &mut ct[start..end] {
            *byte ^= 0xA5;
        }

        fs::write(&enc, &ct).unwrap();

        let err = decrypt_file(&enc, Some(&back), pw).unwrap_err();
        assert!(
            matches!(err, enc_file::EncFileError::Crypto),
            "alg={:?}",
            alg
        );
    }
}

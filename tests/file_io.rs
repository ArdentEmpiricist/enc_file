//! File I/O roundtrips for both algorithms (streaming defaults depend on your library).

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use enc_file::{AeadAlg, EncryptOptions, decrypt_file, encrypt_file};
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

fn write_blob(path: &Path, len: usize) {
    let mut data = vec![0u8; len];
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

#[test]
fn encrypt_decrypt_files_roundtrip_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.enc");
        let back_path = dir.path().join("back.bin");

        write_blob(&in_path, mib(1) + kib(16));

        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        let pw = SecretString::new("pw".into());
        encrypt_file(&in_path, Some(&enc_path), pw.clone(), opts).unwrap();
        decrypt_file(&enc_path, Some(&back_path), pw).unwrap();

        assert_eq!(slurp(&in_path), slurp(&back_path), "alg={alg:?}");
    }
}

#[test]
fn big_file_roundtrip_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.enc");
        let back_path = dir.path().join("back.bin");

        write_blob(&in_path, mib(2));

        let mut opts = EncryptOptions::default();
        opts.alg = alg;

        let pw = SecretString::new("pw".into());
        encrypt_file(&in_path, Some(&enc_path), pw.clone(), opts).unwrap();
        decrypt_file(&enc_path, Some(&back_path), pw).unwrap();

        assert_eq!(slurp(&in_path), slurp(&back_path), "alg={alg:?}");
    }
}

#[test]
fn nonexistent_input_yields_error() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.bin");
    let out = dir.path().join("out.enc");

    let opts = EncryptOptions::default();
    let pw = SecretString::new("pw".into());

    let res = encrypt_file(&missing, Some(&out), pw, opts);
    assert!(res.is_err(), "Encrypting a non-existent file should fail");
}

#[test]
fn output_overwrite_behavior() {
    // This test assumes the library *does not* force-overwrite unless configured.
    // If you later reintroduce overwrite flags, adjust accordingly.
    let dir = tempdir().unwrap();
    let in_path = dir.path().join("in.bin");
    let out_path = dir.path().join("out.enc");

    write_blob(&in_path, kib(64));
    fs::write(&out_path, b"pre-existing").unwrap();

    let mut opts = EncryptOptions::default();
    opts.alg = AeadAlg::XChaCha20Poly1305;

    let pw = SecretString::new("pw".into());
    let res = encrypt_file(&in_path, Some(&out_path), pw, opts);

    // Depending on your library policy:
    // If you block overwriting by default, expect Err; else expect Ok.
    // Here we expect Err to be safe-by-default:
    assert!(
        res.is_err(),
        "If you prefer 'allow overwrite', change this assertion."
    );
}

#[test]
fn keymap_save_load_roundtrip_and_streaming_error() {
    use enc_file::{EncFileError, EncryptOptions, KeyMap, load_keymap, save_keymap};
    use secrecy::SecretString;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let path_ok = dir.path().join("keymap.enc");
    let path_err = dir.path().join("keymap_streaming.enc");

    let mut km = KeyMap::new();
    km.insert("service".into(), "secret123".into());
    km.insert("other".into(), "p@ss!".into());

    let pw = SecretString::new("pw".into());

    // --- Case 1: save/load works normally (stream=false) ---
    let opts_ok = EncryptOptions::default();
    save_keymap(&path_ok, pw.clone(), &km, &opts_ok).unwrap();
    let loaded = load_keymap(&path_ok, pw.clone()).unwrap();
    assert_eq!(loaded, km);

    // --- Case 2: streaming must return the expected Invalid error ---
    let mut opts_stream = EncryptOptions::default();
    opts_stream.stream = true;

    let err =
        save_keymap(&path_err, pw, &km, &opts_stream).expect_err("streaming keymap should fail");
    match err {
        EncFileError::Invalid(msg) => {
            assert_eq!(msg, "keymap: streaming not supported");
        }
        other => panic!("unexpected error type: {other:?}"),
    }
}

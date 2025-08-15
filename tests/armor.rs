//! ASCII-armor roundtrip for both algorithms.

use enc_file::{AeadAlg, EncryptOptions, decrypt_bytes, encrypt_bytes};
use secrecy::SecretString;

const KIB: usize = 1024;

#[inline]
fn kib(n: usize) -> usize {
    n.saturating_mul(KIB)
}

#[test]
fn armor_roundtrip_and_detection_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions {
            armor: true,
            alg,
            ..EncryptOptions::default()
        };

        let msg = vec![0x41; kib(4)]; // 'A' repeated
        let ct = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();

        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, msg, "alg={alg:?}");
    }
}

#[test]
fn file_roundtrip_with_armor_both_algs() {
    use enc_file::{AeadAlg, EncryptOptions, decrypt_file, encrypt_file};
    use secrecy::SecretString;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.asc");
        let out_path = dir.path().join("back.bin");

        File::create(&in_path)
            .unwrap()
            .write_all(b"Hello Armor!")
            .unwrap();

        let opts = EncryptOptions {
            alg,
            armor: true,
            ..Default::default()
        };
        let pw = SecretString::new("pw".into());

        encrypt_file(&in_path, Some(&enc_path), pw.clone(), opts).unwrap();
        decrypt_file(&enc_path, Some(&out_path), pw).unwrap();

        assert_eq!(
            fs::read(&in_path).unwrap(),
            fs::read(&out_path).unwrap(),
            "alg={alg:?}"
        );
    }
}

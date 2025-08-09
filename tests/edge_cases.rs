//! Edge-case tests for both algorithms (empty, tiny, boundary, armor toggle).

use enc_file::{AeadAlg, EncryptOptions, decrypt_bytes, encrypt_bytes};
use secrecy::SecretString;

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

#[test]
fn empty_plaintext_roundtrip_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions {
            alg,
            ..Default::default()
        };
        let msg: &[u8] = &[];

        let ct = encrypt_bytes(msg, pw.clone(), &opts).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, msg, "alg={:?}", alg);
    }
}

#[test]
fn tiny_plaintext_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions {
            alg,
            ..Default::default()
        };
        let msg = b"x";

        let ct = encrypt_bytes(msg, pw.clone(), &opts).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, msg, "alg={:?}", alg);
    }
}

#[test]
fn boundary_sized_plaintext_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions {
            alg,
            ..Default::default()
        };
        let msg = vec![0u8; mib(1) + kib(64) + 7];

        let ct = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, msg, "alg={:?}", alg);
    }
}

#[test]
fn armor_on_off_consistency_both_algs() {
    let algs = [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv];

    for &alg in &algs {
        let pw = SecretString::new("pw".into());
        let mut opts = EncryptOptions {
            alg,
            ..Default::default()
        };

        let msg = vec![0xCC; kib(8)];

        // without armor
        let ct_bin = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();

        // with armor
        opts.armor = true;
        let ct_arm = encrypt_bytes(&msg, pw.clone(), &opts).unwrap();

        // both should decrypt correctly
        let pt_bin = decrypt_bytes(&ct_bin, pw.clone()).unwrap();
        let pt_arm = decrypt_bytes(&ct_arm, pw).unwrap();

        assert_eq!(pt_bin, msg, "alg={:?}", alg);
        assert_eq!(pt_arm, msg, "alg={:?}", alg);
    }
}

//! Property-based streaming roundtrip for *both* algorithms.

use std::fs;
use std::io::Read;

use enc_file::{AeadAlg, EncryptOptions, decrypt_file, encrypt_file};
use secrecy::SecretString;
use tempfile::tempdir;

use proptest::prelude::*;

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

fn streaming_opts(alg: AeadAlg) -> EncryptOptions {
    let mut opts = EncryptOptions::default();
    opts.alg = alg;
    opts.stream = true;
    opts
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        timeout: 60_000,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_round_trip_streaming_with_kdf(
        size in 0usize..mib(2),
        alg in prop_oneof![Just(AeadAlg::XChaCha20Poly1305), Just(AeadAlg::Aes256GcmSiv)],
    ) {
        let dir = tempdir().unwrap();
        let in_path = dir.path().join("in.bin");
        let enc_path = dir.path().join("out.enc");
        let back_path = dir.path().join("back.bin");

        // Fill with deterministic pattern
        let mut data = vec![0u8; size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(1103515245).wrapping_add(12345) as u8;
        }
        fs::write(&in_path, &data).unwrap();

        let pw = SecretString::new("proptest-stream".into());
        encrypt_file(&in_path, Some(&enc_path), pw.clone(), streaming_opts(alg)).unwrap();
        decrypt_file(&enc_path, Some(&back_path), pw).unwrap();

        let mut round = Vec::new();
        std::fs::File::open(&back_path).unwrap().read_to_end(&mut round).unwrap();

        prop_assert_eq!(round, data);
    }
}

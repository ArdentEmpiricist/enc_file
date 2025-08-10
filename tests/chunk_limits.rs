use assert_fs::prelude::*;
use secrecy::SecretString;

use enc_file::{AeadAlg, EncFileError, EncryptOptions, decrypt_file, encrypt_file_streaming};

fn setup_small_input() -> (assert_fs::TempDir, std::path::PathBuf, SecretString) {
    let td = assert_fs::TempDir::new().expect("tempdir");
    let input = td.child("in.bin");
    input.write_binary(b"tiny input").expect("write");
    let pw = SecretString::new("pw".to_string().into());
    (td, input.path().to_path_buf(), pw)
}

/// chunk_size == 0 -> treated as default and succeeds for both algorithms.
#[test]
fn streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs() {
    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv] {
        let (td, in_path, pw) = setup_small_input();

        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: 0, // sentinel -> default
            ..Default::default()
        };

        let enc_path = encrypt_file_streaming(&in_path, None, pw.clone(), opts)
            .expect("encrypt_file_streaming should succeed with chunk_size=0");

        // round-trip sanity: decrypt to a chosen path
        let out = td.child("roundtrip.bin");
        let back =
            decrypt_file(&enc_path, Some(out.path()), pw).expect("decrypt_file should succeed");
        assert!(back.exists());

        td.close().ok();
    }
}

/// chunk_size > (u32::MAX - 16) must be rejected up-front for both algorithms.
/// NOTE: we rely on early validation — the function should error before any huge buffer allocation.
#[test]
fn streaming_rejects_oversized_chunk_for_both_algs() {
    const TAG: usize = 16;
    let too_big = (u32::MAX as usize)
        .checked_sub(TAG)
        .and_then(|v| v.checked_add(1))
        .expect("usize math");

    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv] {
        let (td, in_path, pw) = setup_small_input();

        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: too_big,
            ..Default::default()
        };

        let res = encrypt_file_streaming(&in_path, None, pw, opts);
        match res {
            Err(EncFileError::Invalid(msg)) => {
                // adjust substrings if your exact text differs
                assert!(
                    msg.contains("chunk_size") || msg.contains("32-bit frame"),
                    "unexpected Invalid message: {msg}"
                );
            }
            other => panic!(
                "expected Invalid error for oversized chunk_size, got: {:?}",
                other
            ),
        }

        td.close().ok();
    }
}

/// A small, valid chunk size (e.g. 4 KiB) should work for both algorithms.
#[test]
fn streaming_accepts_small_reasonable_chunk_for_both_algs() {
    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv] {
        let (td, in_path, pw) = setup_small_input();

        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: 4096,
            ..Default::default()
        };

        let enc_path = encrypt_file_streaming(&in_path, None, pw, opts)
            .expect("encrypt_file_streaming should succeed with 4 KiB chunk");
        assert!(enc_path.exists());

        td.close().ok();
    }
}

#[test]
fn streaming_accepts_max_boundary_chunk_size() {
    use assert_fs::prelude::*;
    use enc_file::{EncryptOptions, encrypt_file_streaming};
    use secrecy::SecretString;

    let td = assert_fs::TempDir::new().unwrap();
    let input = td.child("in.bin");
    input.write_binary(b"x").unwrap();

    const TAG: usize = 16;
    let max_ok = (u32::MAX as usize) - TAG;

    let pw = SecretString::new("pw".to_string().into());
    let opts = EncryptOptions {
        stream: true,
        chunk_size: max_ok,
        ..Default::default()
    };
    let out = encrypt_file_streaming(input.path(), None, pw, opts)
        .expect("max boundary should be accepted");
    assert!(out.exists());
    td.close().ok();
}

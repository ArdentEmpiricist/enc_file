use enc_file::{AeadAlg, EncFileError, EncryptOptions, encrypt_file_streaming};
use secrecy::SecretString;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

// Helper: Write a binary blob of a specific length
fn write_blob(path: &PathBuf, len: usize) {
    let data = vec![0u8; len];
    fs::write(path, &data).unwrap();
}

// Helper: Read all bytes from a file
fn slurp(path: &PathBuf) -> Vec<u8> {
    fs::read(path).unwrap()
}

// Default password for tests
fn test_pw() -> SecretString {
    SecretString::new("pw".into())
}

// Get test algorithms
fn test_algs() -> [AeadAlg; 2] {
    [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv]
}

#[test]
fn streaming_rejects_oversized_chunk_for_both_algs() {
    println!("[TEST] streaming_rejects_oversized_chunk_for_both_algs: starting");
    let input_len = 10;
    let oversized_chunk = u32::MAX as usize; // Deliberately too large (AEAD tag is +16 bytes)
    for &alg in &test_algs() {
        println!("[TEST] Trying algorithm: {:?}", alg);
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let outfile = dir.path().join("out.enc");
        write_blob(&infile, input_len);
        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: oversized_chunk,
            ..Default::default()
        };
        let result = encrypt_file_streaming(&infile, Some(&outfile), test_pw(), opts);
        match result {
            Err(EncFileError::Invalid(ref msg)) if msg.contains("chunk size") => {
                println!(
                    "[TEST] streaming_rejects_oversized_chunk_for_both_algs: got expected error for {:?}: {}",
                    alg, msg
                )
            }
            Err(ref e) => println!(
                "[TEST] streaming_rejects_oversized_chunk_for_both_algs: got unexpected error for {:?}: {:?}",
                alg, e
            ),
            Ok(_) => println!(
                "[TEST] streaming_rejects_oversized_chunk_for_both_algs: unexpected success for {:?}",
                alg
            ),
        }
        assert!(result.is_err());
    }
    println!("[TEST] streaming_rejects_oversized_chunk_for_both_algs: finished");
}

/// This test attempts a ~4 GiB allocation (max boundary) and is ignored by default.
/// Run explicitly with: `cargo test -- --ignored`
#[ignore]
#[test]
fn streaming_accepts_max_boundary_chunk_size() {
    println!("[TEST] streaming_accepts_max_boundary_chunk_size: starting");
    let input_len = 10;
    let max_chunk = (u32::MAX - 16) as usize; // Maximum allowed chunk size for streaming
    for &alg in &test_algs() {
        println!("[TEST] Trying algorithm: {:?}", alg);
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let outfile = dir.path().join("out.enc");
        write_blob(&infile, input_len);
        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: max_chunk,
            ..Default::default()
        };
        let result = encrypt_file_streaming(&infile, Some(&outfile), test_pw(), opts);
        match result {
            Ok(ref path) => println!(
                "[TEST] streaming_accepts_max_boundary_chunk_size: succeeded for {:?}, out: {:?}",
                alg, path
            ),
            Err(ref e) => println!(
                "[TEST] streaming_accepts_max_boundary_chunk_size: unexpected error for {:?}: {:?}",
                alg, e
            ),
        }
        assert!(result.is_ok());
    }
    println!("[TEST] streaming_accepts_max_boundary_chunk_size: finished");
}

#[test]
fn streaming_accepts_small_reasonable_chunk_for_both_algs() {
    println!("[TEST] streaming_accepts_small_reasonable_chunk_for_both_algs: starting");
    let input_len = 10;
    let small_chunk = 8; // Small but valid
    for &alg in &test_algs() {
        println!("[TEST] Trying algorithm: {:?}", alg);
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let outfile = dir.path().join("out.enc");
        write_blob(&infile, input_len);
        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: small_chunk,
            ..Default::default()
        };
        let result = encrypt_file_streaming(&infile, Some(&outfile), test_pw(), opts);
        match result {
            Ok(ref path) => println!(
                "[TEST] streaming_accepts_small_reasonable_chunk_for_both_algs: succeeded for {:?}, out: {:?}",
                alg, path
            ),
            Err(ref e) => println!(
                "[TEST] streaming_accepts_small_reasonable_chunk_for_both_algs: unexpected error for {:?}: {:?}",
                alg, e
            ),
        }
        assert!(result.is_ok());
    }
    println!("[TEST] streaming_accepts_small_reasonable_chunk_for_both_algs: finished");
}

#[test]
fn streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs() {
    println!("[TEST] streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs: starting");
    let input_len = 10;
    let zero_chunk = 0; // Should default internally (usually 1 MiB)
    for &alg in &test_algs() {
        println!("[TEST] Trying algorithm: {:?}", alg);
        let dir = tempdir().unwrap();
        let infile = dir.path().join("in.bin");
        let outfile = dir.path().join("out.enc");
        write_blob(&infile, input_len);
        let opts = EncryptOptions {
            alg,
            stream: true,
            chunk_size: zero_chunk,
            ..Default::default()
        };
        let result = encrypt_file_streaming(&infile, Some(&outfile), test_pw(), opts);
        match result {
            Ok(ref path) => println!(
                "[TEST] streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs: succeeded for {:?}, out: {:?}",
                alg, path
            ),
            Err(ref e) => println!(
                "[TEST] streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs: unexpected error for {:?}: {:?}",
                alg, e
            ),
        }
        assert!(result.is_ok());
    }
    println!("[TEST] streaming_zero_chunk_size_defaults_and_succeeds_for_both_algs: finished");
}

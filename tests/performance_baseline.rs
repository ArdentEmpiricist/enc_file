//! Performance baseline tests to measure improvements.

use enc_file::{encrypt_file_streaming, decrypt_file, EncryptOptions, AeadAlg};
use secrecy::SecretString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use tempfile::tempdir;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

fn write_test_data(path: &Path, size: usize) {
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(1664525).wrapping_add(1013904223) as u8;
    }
    fs::File::create(path).unwrap().write_all(&data).unwrap();
}

fn test_password() -> SecretString {
    SecretString::new("test_password_123".into())
}

#[test]
fn baseline_streaming_performance_xchacha20() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.enc");
    let decrypted = dir.path().join("decrypted.bin");

    // Test with 10 MiB file - large enough to see streaming benefits
    let file_size = 10 * MIB;
    write_test_data(&input, file_size);

    let opts = EncryptOptions {
        alg: AeadAlg::XChaCha20Poly1305,
        stream: true,
        chunk_size: MIB, // 1 MiB chunks
        ..Default::default()
    };

    let password = test_password();

    // Measure encryption time
    let start = Instant::now();
    encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
    let encrypt_time = start.elapsed();

    // Measure decryption time
    let start = Instant::now();
    decrypt_file(&encrypted, Some(&decrypted), password).unwrap();
    let decrypt_time = start.elapsed();

    println!("XChaCha20 Baseline (10 MiB, 1 MiB chunks):");
    println!("  Encryption: {:?}", encrypt_time);
    println!("  Decryption: {:?}", decrypt_time);

    // Verify correctness
    let original = fs::read(&input).unwrap();
    let restored = fs::read(&decrypted).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn baseline_streaming_performance_aes() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.enc");
    let decrypted = dir.path().join("decrypted.bin");

    // Test with 10 MiB file
    let file_size = 10 * MIB;
    write_test_data(&input, file_size);

    let opts = EncryptOptions {
        alg: AeadAlg::Aes256GcmSiv,
        stream: true,
        chunk_size: MIB, // 1 MiB chunks
        ..Default::default()
    };

    let password = test_password();

    // Measure encryption time
    let start = Instant::now();
    encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
    let encrypt_time = start.elapsed();

    // Measure decryption time
    let start = Instant::now();
    decrypt_file(&encrypted, Some(&decrypted), password).unwrap();
    let decrypt_time = start.elapsed();

    println!("AES-GCM-SIV Baseline (10 MiB, 1 MiB chunks):");
    println!("  Encryption: {:?}", encrypt_time);
    println!("  Decryption: {:?}", decrypt_time);

    // Verify correctness
    let original = fs::read(&input).unwrap();
    let restored = fs::read(&decrypted).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn baseline_chunk_size_comparison() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.bin");
    
    // Test with 20 MiB file
    let file_size = 20 * MIB;
    write_test_data(&input, file_size);

    let password = test_password();

    // Test different chunk sizes
    let chunk_sizes = [64 * KIB, 256 * KIB, MIB, 4 * MIB];
    
    for &chunk_size in &chunk_sizes {
        let encrypted = dir.path().join(format!("encrypted_{}.enc", chunk_size));
        let decrypted = dir.path().join(format!("decrypted_{}.bin", chunk_size));

        let opts = EncryptOptions {
            alg: AeadAlg::XChaCha20Poly1305,
            stream: true,
            chunk_size,
            ..Default::default()
        };

        // Measure encryption time
        let start = Instant::now();
        encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
        let encrypt_time = start.elapsed();

        // Measure decryption time
        let start = Instant::now();
        decrypt_file(&encrypted, Some(&decrypted), password.clone()).unwrap();
        let decrypt_time = start.elapsed();

        println!("Chunk size {} KiB:", chunk_size / KIB);
        println!("  Encryption: {:?}", encrypt_time);
        println!("  Decryption: {:?}", decrypt_time);
    }
}
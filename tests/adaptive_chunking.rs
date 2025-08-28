//! Tests for chunk size optimization

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
fn adaptive_chunk_size_small_files() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("small.bin");
    let encrypted = dir.path().join("small.enc");
    let decrypted = dir.path().join("small.dec");

    // Small file - should use optimal smaller chunk size
    let file_size = 512 * KIB; // 512 KB file
    write_test_data(&input, file_size);

    let opts = EncryptOptions {
        alg: AeadAlg::XChaCha20Poly1305,
        stream: true,
        chunk_size: 0, // Use automatic optimization
        ..Default::default()
    };

    let password = test_password();

    let start = Instant::now();
    encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    decrypt_file(&encrypted, Some(&decrypted), password).unwrap();
    let decrypt_time = start.elapsed();

    println!("Small file (512 KB) with adaptive chunking:");
    println!("  Encryption: {:?}", encrypt_time);
    println!("  Decryption: {:?}", decrypt_time);

    // Verify correctness
    let original = fs::read(&input).unwrap();
    let restored = fs::read(&decrypted).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn adaptive_chunk_size_medium_files() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("medium.bin");
    let encrypted = dir.path().join("medium.enc");
    let decrypted = dir.path().join("medium.dec");

    // Medium file - should use default chunk size
    let file_size = 50 * MIB;
    write_test_data(&input, file_size);

    let opts = EncryptOptions {
        alg: AeadAlg::XChaCha20Poly1305,
        stream: true,
        chunk_size: 0, // Use automatic optimization
        ..Default::default()
    };

    let password = test_password();

    let start = Instant::now();
    encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    decrypt_file(&encrypted, Some(&decrypted), password).unwrap();
    let decrypt_time = start.elapsed();

    println!("Medium file (50 MB) with adaptive chunking:");
    println!("  Encryption: {:?}", encrypt_time);
    println!("  Decryption: {:?}", decrypt_time);

    // Verify correctness
    let original = fs::read(&input).unwrap();
    let restored = fs::read(&decrypted).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn compare_chunk_sizes_performance() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("compare.bin");
    
    // Use 20 MB file for comparison
    let file_size = 20 * MIB;
    write_test_data(&input, file_size);

    let password = test_password();
    
    // Test different chunk sizes
    let chunk_sizes = [0, 256 * KIB, MIB, 4 * MIB]; // 0 = auto, 256KB, 1MB, 4MB
    let chunk_names = ["Auto", "256KB", "1MB", "4MB"];
    
    for (i, &chunk_size) in chunk_sizes.iter().enumerate() {
        let encrypted = dir.path().join(format!("compare_{}.enc", i));
        let decrypted = dir.path().join(format!("compare_{}.dec", i));

        let opts = EncryptOptions {
            alg: AeadAlg::XChaCha20Poly1305,
            stream: true,
            chunk_size,
            ..Default::default()
        };

        let start = Instant::now();
        encrypt_file_streaming(&input, Some(&encrypted), password.clone(), opts).unwrap();
        let encrypt_time = start.elapsed();

        let start = Instant::now();
        decrypt_file(&encrypted, Some(&decrypted), password.clone()).unwrap();
        let decrypt_time = start.elapsed();

        println!("{} chunk:", chunk_names[i]);
        println!("  Encryption: {:?}", encrypt_time);
        println!("  Decryption: {:?}", decrypt_time);
        
        // Verify correctness
        let original = fs::read(&input).unwrap();
        let restored = fs::read(&decrypted).unwrap();
        assert_eq!(original, restored);
    }
}
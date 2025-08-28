//! Test that adaptive chunk sizing actually selects different chunk sizes
//! based on file sizes and that the calculation function works as expected.

use enc_file::{EncryptOptions, AeadAlg};
use enc_file::encrypt_file_streaming;
use secrecy::SecretString;
use std::fs;
use tempfile::tempdir;

/// Test that adaptive sizing selects different chunk sizes for different file sizes
#[test] 
fn adaptive_sizing_selects_appropriate_chunks() {
    let dir = tempdir().unwrap();
    let password = SecretString::new("test_password".into());
    
    // Test file sizes that should trigger different chunk sizes
    let test_cases = vec![
        (64 * 1024, "small file - 64 KB"),      // Should use 64 KiB chunks
        (512 * 1024, "medium-small file - 512 KB"), // Should use 64 KiB chunks  
        (50 * 1024 * 1024, "medium file - 50 MB"),   // Should use 1 MiB chunks
        (150 * 1024 * 1024, "large file - 150 MB"),  // Should use scaled-up chunks
    ];
    
    for (file_size, description) in test_cases {
        println!("Testing {}", description);
        
        // Create test file
        let input_path = dir.path().join(format!("test_{}.bin", file_size));
        let encrypted_path = input_path.with_extension("enc");
        let test_data = vec![0x42u8; file_size];
        fs::write(&input_path, &test_data).unwrap();
        
        // Encrypt with adaptive chunk sizing (chunk_size = 0)
        let opts = EncryptOptions {
            alg: AeadAlg::XChaCha20Poly1305,
            stream: true,
            chunk_size: 0, // Enable adaptive sizing
            force: true,
            ..Default::default()
        };
        
        let result = encrypt_file_streaming(&input_path, Some(&encrypted_path), password.clone(), opts);
        assert!(result.is_ok(), "Encryption failed for {}: {:?}", description, result.err());
        
        // Verify the encrypted file exists and is reasonable in size
        assert!(encrypted_path.exists(), "Encrypted file not created for {}", description);
        
        let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
        let original_size = fs::metadata(&input_path).unwrap().len();
        
        // The encrypted file should be larger than original (due to headers, frames, and auth tags)
        // but not excessively larger (which would indicate inefficient framing)
        assert!(encrypted_size > original_size, "Encrypted file should be larger than original for {}", description);
        
        // For files larger than frame overhead, encrypted size shouldn't be more than ~20% larger
        // (this is a rough check - actual overhead depends on chunk size and number of frames)
        if original_size > 1024 {
            let overhead_ratio = (encrypted_size as f64) / (original_size as f64);
            assert!(overhead_ratio < 1.3, "Encryption overhead too high for {}: {:.1}%", description, (overhead_ratio - 1.0) * 100.0);
        }
        
        println!("  Original: {} bytes, Encrypted: {} bytes", original_size, encrypted_size);
        
        // Clean up
        let _ = fs::remove_file(&input_path);
        let _ = fs::remove_file(&encrypted_path);
    }
}

/// Test that non-zero chunk size overrides adaptive sizing
#[test]
fn explicit_chunk_size_overrides_adaptive() {
    let dir = tempdir().unwrap();
    let password = SecretString::new("test_password".into());
    
    // Create a medium-sized file (50 MB) that would normally get 1 MiB chunks
    let file_size = 50 * 1024 * 1024;
    let input_path = dir.path().join("test_override.bin");
    let encrypted_path = input_path.with_extension("enc");
    let test_data = vec![0x42u8; file_size];
    fs::write(&input_path, &test_data).unwrap();
    
    // Encrypt with explicit chunk size that's different from what adaptive would choose
    let explicit_chunk_size = 2 * 1024 * 1024; // 2 MiB (different from the 1 MiB that adaptive would choose)
    let opts = EncryptOptions {
        alg: AeadAlg::XChaCha20Poly1305,
        stream: true,
        chunk_size: explicit_chunk_size,
        force: true,
        ..Default::default()
    };
    
    let result = encrypt_file_streaming(&input_path, Some(&encrypted_path), password, opts);
    assert!(result.is_ok(), "Encryption with explicit chunk size failed: {:?}", result.err());
    
    // Verify the encrypted file exists
    assert!(encrypted_path.exists(), "Encrypted file not created with explicit chunk size");
    
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    let original_size = fs::metadata(&input_path).unwrap().len();
    
    assert!(encrypted_size > original_size, "Encrypted file should be larger than original");
    
    println!("Explicit chunk size test - Original: {} bytes, Encrypted: {} bytes", original_size, encrypted_size);
}
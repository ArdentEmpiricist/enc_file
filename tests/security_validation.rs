//! Security validation tests

use enc_file::{encrypt_file, decrypt_bytes, EncryptOptions};
use secrecy::SecretString;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

fn test_password() -> SecretString {
    SecretString::new("test_password_123".into())
}

#[test]
fn test_file_size_validation() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.enc");

    // Create a reasonable size file for testing
    let data = vec![0u8; 1024];
    fs::File::create(&input).unwrap().write_all(&data).unwrap();

    let opts = EncryptOptions::default();
    let password = test_password();

    // This should work fine
    let result = encrypt_file(&input, Some(&encrypted), password, opts);
    assert!(result.is_ok());
}

#[test]
fn test_ciphertext_length_validation() {
    let password = test_password();
    let opts = EncryptOptions::default();

    // Create a reasonable size input
    let data = vec![42u8; 1024];
    let encrypted = enc_file::encrypt_bytes(&data, password.clone(), &opts).unwrap();

    // This should work fine
    let result = decrypt_bytes(&encrypted, password);
    assert!(result.is_ok());
}

#[test]
fn test_malformed_frame_detection() {
    // Test that oversized frames are properly rejected during streaming
    // We'll test the chunk size validation through the public API
    
    use enc_file::validate_chunk_size_for_streaming;
    
    // Test chunk size that would exceed maximum with AEAD tag
    let max_allowed_chunk = (u32::MAX as usize) - 16; // Leave room for AEAD tag
    assert!(validate_chunk_size_for_streaming(max_allowed_chunk).is_ok());
    
    // This should fail - chunk too large for 32-bit frame format
    let oversized_chunk = (u32::MAX as usize) - 15; // Not enough room for AEAD tag
    assert!(validate_chunk_size_for_streaming(oversized_chunk).is_err());
    
    // Test zero chunk size
    assert!(validate_chunk_size_for_streaming(0).is_err());
}

#[test]
fn test_chunk_size_boundary_validation() {
    use enc_file::validate_chunk_size_for_streaming;
    
    // Test that chunk size validation works correctly
    assert!(validate_chunk_size_for_streaming(0).is_err()); // Zero not allowed
    assert!(validate_chunk_size_for_streaming(1024).is_ok()); // Small size OK
    assert!(validate_chunk_size_for_streaming(1024 * 1024).is_ok()); // 1MB OK
    assert!(validate_chunk_size_for_streaming(8 * 1024 * 1024).is_ok()); // 8MB OK
    
    // Very large chunk size should be rejected
    let max_allowed = (u32::MAX as usize) - 16; // Max with AEAD tag
    assert!(validate_chunk_size_for_streaming(max_allowed).is_ok());
    assert!(validate_chunk_size_for_streaming(max_allowed + 1).is_err());
}

#[test]
fn test_empty_file_handling() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("empty.bin");
    let encrypted = dir.path().join("empty.enc");
    let decrypted = dir.path().join("empty.dec");

    // Create an empty file
    fs::File::create(&input).unwrap();

    let opts = EncryptOptions::default();
    let password = test_password();

    // Encrypt empty file
    encrypt_file(&input, Some(&encrypted), password.clone(), opts).unwrap();
    
    // Decrypt empty file
    enc_file::decrypt_file(&encrypted, Some(&decrypted), password).unwrap();

    // Verify it's still empty
    let result = fs::read(&decrypted).unwrap();
    assert_eq!(result.len(), 0);
}
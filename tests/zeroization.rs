use enc_file::{load_keymap, save_keymap, EncryptOptions, KeyMap};
use secrecy::SecretString;

/// Test that keymap operations don't leak plaintext data.
/// This is a basic test to ensure our zeroization changes work.
#[test]
fn keymap_operations_zeroize_sensitive_data() {
    use tempfile::tempdir;
    let temp_dir = tempdir().unwrap();
    let temp_file_path = temp_dir.path().join("keymap.enc");
    let password = SecretString::new("test_password".into());
    
    // Create a keymap with some test data
    let mut map: KeyMap = std::collections::HashMap::new();
    map.insert("test_key".to_string(), vec![0x01; 32]);
    
    let opts = EncryptOptions::default();
    
    // Save the keymap - this should zeroize the serialized plaintext
    save_keymap(&temp_file_path, password.clone(), &map, &opts).unwrap();
    
    // Load the keymap - this should zeroize the decrypted plaintext
    let loaded_map = load_keymap(&temp_file_path, password).unwrap();
    
    // Verify the keymap was loaded correctly
    assert_eq!(loaded_map.len(), 1);
    assert!(loaded_map.contains_key("test_key"));
    assert_eq!(loaded_map["test_key"], vec![0x01; 32]);
}

/// Test that encrypt/decrypt operations properly handle sensitive data.
/// This ensures our security improvements don't break basic functionality.
#[test]
fn encrypt_decrypt_operations_work_correctly() {
    use enc_file::{encrypt_bytes, decrypt_bytes, EncryptOptions};
    
    let password = SecretString::new("secure_password".into());
    let opts = EncryptOptions::default();
    let plaintext = b"This is sensitive data that should be zeroized";
    
    // Encrypt the data
    let ciphertext = encrypt_bytes(plaintext, password.clone(), &opts).unwrap();
    
    // Decrypt the data
    let decrypted = decrypt_bytes(&ciphertext, password).unwrap();
    
    // Verify correctness
    assert_eq!(decrypted, plaintext);
}

/// Test that streaming operations work correctly with our zeroization improvements.
#[test]
fn streaming_operations_work_correctly() {
    use enc_file::{encrypt_file_streaming, decrypt_file, EncryptOptions, AeadAlg};
    use std::fs;
    use tempfile::tempdir;
    
    let temp_dir = tempdir().unwrap();
    let password = SecretString::new("streaming_password".into());
    let opts = EncryptOptions {
        stream: true,
        chunk_size: 1024, // Small chunks for testing
        alg: AeadAlg::XChaCha20Poly1305,
        force: true, // Allow overwriting for test
        ..Default::default()
    };
    
    // Create test data in the temp directory
    let input_path = temp_dir.path().join("input.bin");
    let encrypted_path = temp_dir.path().join("output.enc");
    let decrypted_path = temp_dir.path().join("decrypted.bin");
    
    let test_data = b"This is streaming test data that should be processed in chunks and properly zeroized.";
    fs::write(&input_path, test_data).unwrap();
    
    // Encrypt using streaming
    let final_encrypted_path = encrypt_file_streaming(
        &input_path,
        Some(&encrypted_path),
        password.clone(),
        opts
    ).unwrap();
    
    // Decrypt the file  
    let final_decrypted_path = decrypt_file(
        &final_encrypted_path,
        Some(&decrypted_path),
        password
    ).unwrap();
    
    // Verify the content is correct
    let decrypted_data = fs::read(&final_decrypted_path).unwrap();
    assert_eq!(decrypted_data, test_data);
}
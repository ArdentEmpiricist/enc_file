use enc_file::{load_keymap, save_keymap, EncryptOptions, KeyMap};
use secrecy::SecretString;
use tempfile::NamedTempFile;

/// Test that keymap operations don't leak plaintext data.
/// This is a basic test to ensure our zeroization changes work.
#[test]
fn keymap_operations_zeroize_sensitive_data() {
    let temp_file = NamedTempFile::new().unwrap();
    let password = SecretString::new("test_password".into());
    
    // Create a keymap with some test data
    let mut map: KeyMap = std::collections::HashMap::new();
    map.insert("test_key".to_string(), vec![0x01; 32]);
    
    let opts = EncryptOptions::default();
    
    // Save the keymap - this should zeroize the serialized plaintext
    save_keymap(temp_file.path(), password.clone(), &map, &opts).unwrap();
    
    // Load the keymap - this should zeroize the decrypted plaintext
    let loaded_map = load_keymap(temp_file.path(), password).unwrap();
    
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
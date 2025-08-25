// Tests for KDF hardening and backward compatibility
use enc_file::{EncryptOptions, KdfParams, decrypt_bytes, encrypt_bytes};
use secrecy::SecretString;

#[test]
fn kdf_default_parameters_are_hardened() {
    let defaults = KdfParams::default();

    // Verify hardened defaults
    assert!(defaults.t_cost >= 3, "Time cost should be at least 3");
    assert!(
        defaults.mem_kib >= 65536,
        "Memory cost should be at least 64 MiB"
    );
    assert!(
        defaults.parallelism >= 1,
        "Parallelism should be at least 1"
    );
    assert!(
        defaults.parallelism <= 4,
        "Parallelism should be reasonable for defaults"
    );
}

#[test]
fn kdf_validation_enforces_minima() {
    let password = SecretString::new("test".into());
    let data = b"test data";

    // Test time cost minimum
    let weak_time = EncryptOptions {
        kdf_params: KdfParams {
            t_cost: 1, // Below minimum of 3
            mem_kib: 65536,
            parallelism: 1,
        },
        ..Default::default()
    };
    let result = encrypt_bytes(data, password.clone(), &weak_time);
    assert!(result.is_err(), "Should reject weak time cost");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("kdf:"),
            "Error should have kdf: prefix"
        );
        assert!(
            e.to_string().contains("time cost"),
            "Error should mention time cost"
        );
    }

    // Test memory cost minimum
    let weak_memory = EncryptOptions {
        kdf_params: KdfParams {
            t_cost: 3,
            mem_kib: 1024, // Below minimum of 64 MiB
            parallelism: 1,
        },
        ..Default::default()
    };
    let result = encrypt_bytes(data, password.clone(), &weak_memory);
    assert!(result.is_err(), "Should reject weak memory cost");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("kdf:"),
            "Error should have kdf: prefix"
        );
        assert!(
            e.to_string().contains("memory cost"),
            "Error should mention memory cost"
        );
    }

    // Test parallelism minimum
    let weak_parallelism = EncryptOptions {
        kdf_params: KdfParams {
            t_cost: 3,
            mem_kib: 65536,
            parallelism: 0, // Below minimum of 1
        },
        ..Default::default()
    };
    let result = encrypt_bytes(data, password.clone(), &weak_parallelism);
    assert!(result.is_err(), "Should reject zero parallelism");
    if let Err(e) = result {
        assert!(
            e.to_string().contains("kdf:"),
            "Error should have kdf: prefix"
        );
        assert!(
            e.to_string().contains("parallelism"),
            "Error should mention parallelism"
        );
    }
}

#[test]
fn kdf_validation_accepts_compliant_parameters() {
    let password = SecretString::new("test".into());
    let data = b"test data for encryption";

    let compliant_opts = EncryptOptions {
        kdf_params: KdfParams {
            t_cost: 3,
            mem_kib: 65536,
            parallelism: 2,
        },
        ..Default::default()
    };

    let encrypted = encrypt_bytes(data, password.clone(), &compliant_opts).unwrap();
    let decrypted = decrypt_bytes(&encrypted, password).unwrap();

    assert_eq!(
        data,
        decrypted.as_slice(),
        "Roundtrip should work with compliant params"
    );
}

#[test]
fn streaming_roundtrip_with_file_id() {
    use enc_file::{decrypt_file, encrypt_file_streaming};
    use std::io::Write;
    use tempfile::NamedTempFile;

    let tmp_input = NamedTempFile::new().unwrap();
    tmp_input
        .as_file()
        .write_all(b"test data for streaming with file id")
        .unwrap();

    let password = SecretString::new("test".into());
    let opts = EncryptOptions {
        stream: true,
        ..Default::default()
    };

    // Encrypt using streaming
    let encrypted_path =
        encrypt_file_streaming(tmp_input.path(), None, password.clone(), opts).unwrap();

    // Verify decryption works (this ensures file_id doesn't break compatibility)
    let tmp_output = NamedTempFile::new().unwrap();
    let output_path = tmp_output.path().with_extension("dec");
    let decrypted_path = decrypt_file(&encrypted_path, Some(&output_path), password).unwrap();
    let decrypted_data = std::fs::read(&decrypted_path).unwrap();

    assert_eq!(
        b"test data for streaming with file id",
        decrypted_data.as_slice()
    );

    // Clean up
    std::fs::remove_file(encrypted_path).ok();
    std::fs::remove_file(decrypted_path).ok();
}

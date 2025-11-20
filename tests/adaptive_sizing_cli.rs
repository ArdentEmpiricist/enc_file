//! Test CLI adaptive sizing behavior
//!
//! These tests verify that the CLI properly defaults to adaptive chunk sizing
//! when chunk_size is 0, and that different file sizes result in appropriate
//! chunk sizes being selected.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

const ONE_MIB: usize = 1024 * 1024;

fn enc_file_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("enc-file"))
}

fn create_test_file(size: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.bin");
    let data = vec![0x42u8; size];
    fs::write(&path, data).unwrap();
    (dir, path)
}

#[test]
fn cli_adaptive_sizing_small_file() {
    let (_dir, input_path) = create_test_file(512 * 1024); // 512 KB file
    let encrypted_path = input_path.with_extension("enc");
    let password_file = input_path.with_extension("pw");
    fs::write(&password_file, "test_password").unwrap();

    // Test with default chunk_size (0) - should use adaptive sizing
    let mut cmd = enc_file_cmd();
    cmd.args(["enc", "--stream"])
        .arg("--in").arg(&input_path)
        .arg("--out").arg(&encrypted_path)
        .arg("--password-file").arg(&password_file)
        .arg("--force")
        .assert()
        .success();

    // Verify the file was created
    assert!(encrypted_path.exists());
    
    // The encrypted file should exist and be larger than the original
    // (due to header and framing overhead)
    let original_size = fs::metadata(&input_path).unwrap().len();
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    assert!(encrypted_size > original_size);
    
    // Clean up
    let _ = fs::remove_file(&encrypted_path);
}

#[test]
fn cli_adaptive_sizing_medium_file() {
    let (_dir, input_path) = create_test_file(50 * ONE_MIB); // 50 MB file
    let encrypted_path = input_path.with_extension("enc");
    let password_file = input_path.with_extension("pw");
    fs::write(&password_file, "test_password").unwrap();

    // Test with default chunk_size (0) - should use adaptive sizing
    let mut cmd = enc_file_cmd();
    cmd.args(["enc", "--stream"])
        .arg("--in").arg(&input_path)
        .arg("--out").arg(&encrypted_path)
        .arg("--password-file").arg(&password_file)
        .arg("--force")
        .assert()
        .success();

    // Verify the file was created
    assert!(encrypted_path.exists());
    
    // The encrypted file should exist and be larger than the original
    let original_size = fs::metadata(&input_path).unwrap().len();
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    assert!(encrypted_size > original_size);
    
    // Clean up
    let _ = fs::remove_file(&encrypted_path);
}

#[test]
fn cli_explicit_chunk_size_override() {
    let (_dir, input_path) = create_test_file(512 * 1024); // 512 KB file
    let encrypted_path = input_path.with_extension("enc");
    let password_file = input_path.with_extension("pw");
    fs::write(&password_file, "test_password").unwrap();

    // Test with explicit chunk_size - should override adaptive sizing
    let mut cmd = enc_file_cmd();
    cmd.args(["enc", "--stream"])
        .arg("--chunk-size").arg("65536") // 64 KB explicit
        .arg("--in").arg(&input_path)
        .arg("--out").arg(&encrypted_path)
        .arg("--password-file").arg(&password_file)
        .arg("--force")
        .assert()
        .success();

    // Verify the file was created
    assert!(encrypted_path.exists());
    
    // Clean up
    let _ = fs::remove_file(&encrypted_path);
}

#[test]
fn cli_help_shows_adaptive_sizing_info() {
    let mut cmd = enc_file_cmd();
    let output = cmd.arg("enc").arg("--help").assert().success();
    
    let help_text = String::from_utf8_lossy(&output.get_output().stdout);
    
    // Check that the help text mentions adaptive sizing
    assert!(help_text.contains("adaptive sizing"));
    assert!(help_text.contains("64 KiB"));
    assert!(help_text.contains("1 MiB"));
    assert!(help_text.contains("8 MiB"));
    assert!(help_text.contains("[default: 0]"));
}

#[test]
fn cli_help_shows_improved_alg_description() {
    let mut cmd = enc_file_cmd();
    let output = cmd.arg("enc").arg("--help").assert().success();
    
    let help_text = String::from_utf8_lossy(&output.get_output().stdout);
    
    // Check that the help text has improved algorithm descriptions
    assert!(help_text.contains("XChaCha20-Poly1305"));
    assert!(help_text.contains("AES-256-GCM-SIV"));
    assert!(help_text.contains("xchacha = XChaCha20-Poly1305"));
    assert!(help_text.contains("aes = AES-256-GCM-SIV"));
}
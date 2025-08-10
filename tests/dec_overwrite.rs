use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use secrecy::SecretString;
use std::process::Command;

use enc_file::{EncryptOptions, encrypt_file};

/// Decrypt with an explicit --out:
/// - without --force => must fail and keep preexisting file intact
/// - with --force    => must succeed and replace contents
#[test]
fn dec_refuses_and_then_overwrites_with_explicit_out() -> Result<(), Box<dyn std::error::Error>> {
    let td = assert_fs::TempDir::new()?;

    // Prepare plaintext
    let plain = td.child("plain.txt");
    plain.write_str("hello secret\n")?;

    // Prepare password + file (create BEFORE any CLI call so it doesn't error out)
    let pw = SecretString::new("pw".to_string().into());
    let pwfile = td.child("pw.txt");
    pwfile.write_str("pw")?;

    // Produce ciphertext via library (avoids depending on enc CLI flags)
    let ct = td.child("cipher.enc");
    let opts = EncryptOptions::default();
    encrypt_file(plain.path(), Some(ct.path()), pw, opts)?;

    // Pre-create a target output with different content
    let out = td.child("out.txt");
    out.write_str("preexisting")?;

    // Decrypt WITHOUT --force -> must fail and keep "preexisting"
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["--password-file"])
        .arg(pwfile.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("use --force"));

    out.assert("preexisting");

    // Decrypt WITH --force -> must succeed and replace content
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--out"])
        .arg(out.path())
        .args(["--password-file"])
        .arg(pwfile.path())
        .args(["--force"])
        .assert()
        .success();

    out.assert("hello secret\n");

    td.close()?;
    Ok(())
}

/// Decrypt to the default output path (strip ".enc" or append ".dec"):
/// - without --out, if the default path already exists, it should fail without --force
/// - with --force, it should overwrite and succeed
#[test]
fn dec_refuses_and_then_overwrites_with_default_out() -> Result<(), Box<dyn std::error::Error>> {
    let td = assert_fs::TempDir::new()?;

    // Prepare a plaintext file whose name matches the default dec target ("data.txt")
    let plain = td.child("data.txt");
    plain.write_str("alpha\nbeta\ngamma\n")?;

    // Password file (create BEFORE CLI call)
    let pwfile = td.child("pw.txt");
    pwfile.write_str("pw")?;

    // Encrypt via library to "data.txt.enc"
    let ct = td.child("data.txt.enc");
    let opts = EncryptOptions::default();
    let pw = SecretString::new("pw".to_string().into());
    encrypt_file(plain.path(), Some(ct.path()), pw, opts)?;

    // Change the plaintext to simulate a preexisting conflicting destination
    plain.write_str("THIS WAS HERE BEFORE DEC\n")?;

    // Decrypt WITHOUT --force (no --out) -> must fail and keep preexisting content
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--password-file"])
        .arg(pwfile.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("use --force"));

    plain.assert("THIS WAS HERE BEFORE DEC\n");

    // Decrypt WITH --force -> must succeed and restore original content
    Command::cargo_bin("enc-file")?
        .args(["dec", "--in"])
        .arg(ct.path())
        .args(["--password-file"])
        .arg(pwfile.path())
        .args(["--force"])
        .assert()
        .success();

    plain.assert("alpha\nbeta\ngamma\n");

    td.close()?;
    Ok(())
}

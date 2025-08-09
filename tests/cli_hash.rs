use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use enc_file::{HashAlg, hash_file, to_hex_lower};

fn write_tmp_file(bytes: &[u8]) -> std::path::PathBuf {
    let dir = tempdir().unwrap();
    let p = dir.path().join("m.txt");
    // Keep dir alive by leaking it (scoped temp for each call is fine in tests)
    std::mem::forget(dir);
    File::create(&p).unwrap().write_all(bytes).unwrap();
    p
}

fn cli_hash_hex(path: &std::path::Path, alg_cli: &str) -> String {
    let mut cmd = Command::cargo_bin("enc-file").unwrap();
    let assert = cmd
        .args(["hash"])
        .arg(path)
        .args(["--alg", alg_cli])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    out.trim().to_string()
}

fn cli_hash_raw(path: &std::path::Path, alg_cli: &str) -> Vec<u8> {
    let mut cmd = Command::cargo_bin("enc-file").unwrap();
    let assert = cmd
        .args(["hash"])
        .arg(path)
        .args(["--alg", alg_cli, "--raw"])
        .assert()
        .success();
    assert.get_output().stdout.clone()
}

#[test]
fn cli_hash_all_algorithms_match_library_hex() {
    // Use a small deterministic input
    let p = write_tmp_file(b"abc");

    // (cli flag, library enum)
    let cases: &[(&str, HashAlg)] = &[
        ("blake3", HashAlg::Blake3),
        ("blake2b", HashAlg::Blake2b),
        ("sha256", HashAlg::Sha256),
        ("sha512", HashAlg::Sha512),
        ("sha3-256", HashAlg::Sha3_256),
        ("sha3-512", HashAlg::Sha3_512),
        ("xxh3-64", HashAlg::Xxh3_64),
        ("xxh3-128", HashAlg::Xxh3_128),
        ("crc32", HashAlg::Crc32),
    ];

    for (alg_cli, alg_enum) in cases {
        // Expected via library API
        let expected = to_hex_lower(&hash_file(&p, *alg_enum).unwrap());

        // Actual from CLI
        let got = cli_hash_hex(&p, alg_cli);
        assert_eq!(got, expected, "mismatch for --alg {alg_cli}");
    }
}

#[test]
fn cli_hash_raw_bytes_match_library_digest_once() {
    // Pick one representative algorithm to verify --raw path
    let p = write_tmp_file(b"abc");
    let alg_cli = "xxh3-128";
    let lib = hash_file(&p, HashAlg::Xxh3_128).unwrap();
    let cli = cli_hash_raw(&p, alg_cli);
    assert_eq!(cli, lib, "--raw bytes mismatch for --alg {alg_cli}");
}

#[test]
fn cli_hash_aliases_match_canonical() {
    use assert_cmd::Command;
    use enc_file::{HashAlg, hash_file, to_hex_lower};
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    // Prepare input
    let dir = tempdir().unwrap();
    let p = dir.path().join("m.txt");
    File::create(&p).unwrap().write_all(b"alias-check").unwrap();

    // (canonical, aliases..., corresponding library enum)
    let cases: &[(&str, &[&str], HashAlg)] = &[
        // XXH3-64
        ("xxh3-64", &["xxh364"], HashAlg::Xxh3_64),
        // XXH3-128
        ("xxh3-128", &["xxh3128"], HashAlg::Xxh3_128),
        // SHA3 variants (new aliases included)
        ("sha3-256", &["sha3256", "sha3_256"], HashAlg::Sha3_256),
        ("sha3-512", &["sha3512", "sha3_512"], HashAlg::Sha3_512),
    ];

    for (canonical, aliases, alg_enum) in cases {
        // Expected digest via library API
        let expected_hex = to_hex_lower(&hash_file(&p, *alg_enum).unwrap());

        // Check canonical
        let mut cmd = Command::cargo_bin("enc-file").unwrap();
        let assert = cmd
            .args(["hash"])
            .arg(&p)
            .args(["--alg", canonical])
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout)
            .trim()
            .to_string();
        assert_eq!(out, expected_hex, "canonical failed for --alg {canonical}");

        // Check aliases
        for &alias in *aliases {
            let mut cmd = Command::cargo_bin("enc-file").unwrap();
            let assert = cmd
                .args(["hash"])
                .arg(&p)
                .args(["--alg", alias])
                .assert()
                .success();
            let out = String::from_utf8_lossy(&assert.get_output().stdout)
                .trim()
                .to_string();
            assert_eq!(out, expected_hex, "alias {alias} != canonical {canonical}");
        }
    }
}

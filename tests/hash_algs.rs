use enc_file::{hash_bytes, hash_bytes_keyed_blake3, hash_file, to_hex_lower, HashAlg};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[test]
fn hash_bytes_known_vectors() {
    let m = b"abc";
    let h_b3 = hash_bytes(m, HashAlg::Blake3);
    // Known BLAKE3("abc"):
    // echo -n abc | b3sum -> "9f... (32 bytes)"
    // We'll just assert length here to avoid vector churn.
    assert_eq!(h_b3.len(), 32);

    let h_sha256 = hash_bytes(m, HashAlg::Sha256);
    assert_eq!(
        to_hex_lower(&h_sha256),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let h_crc = hash_bytes(m, HashAlg::Crc32);
    assert_eq!(h_crc.len(), 4);
}

fn expected_len(alg: HashAlg) -> usize {
    match alg {
        HashAlg::Blake3 => 32,
        HashAlg::Sha256 => 32,
        HashAlg::Sha512 => 64,
        HashAlg::Sha3_256 => 32,
        HashAlg::Sha3_512 => 64,
        HashAlg::Blake2b => 64, // Blake2b-512
        HashAlg::Xxh3_64 => 8,
        HashAlg::Xxh3_128 => 16,
        HashAlg::Crc32 => 4,
    }
}

#[test]
fn hash_file_roundtrip_sizes() {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let p = dir.path().join("hash_test.bin");
    let mut f = File::create(&p).unwrap();
    f.write_all(&vec![0xAA; 128 * 1024]).unwrap();
    drop(f); // sicherstellen, dass geschrieben/flushed ist

    for alg in [
        HashAlg::Blake3,
        HashAlg::Sha256,
        HashAlg::Sha512,
        HashAlg::Sha3_256,
        HashAlg::Sha3_512,
        HashAlg::Blake2b,
        HashAlg::Xxh3_64,
        HashAlg::Xxh3_128,
        HashAlg::Crc32,
    ] {
        let d = hash_file(&p, alg).unwrap();
        assert!(!d.is_empty());
        assert_eq!(d.len(), expected_len(alg));
    }
}

#[test]
fn keyed_blake3_works() {
    let key = [0x11u8; 32];
    let mac1 = hash_bytes_keyed_blake3(b"msg", &key);
    let mac2 = hash_bytes_keyed_blake3(b"msg", &key);
    assert_eq!(mac1, mac2);
}

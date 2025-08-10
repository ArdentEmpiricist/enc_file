// tests/no_plain_chunks.rs
#![allow(clippy::needless_pass_by_value)]

use enc_file::{
    AeadAlg, EncryptOptions, KdfAlg, KdfParams, encrypt_bytes, encrypt_file,
    encrypt_file_streaming, looks_armored,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use secrecy::SecretString;
use std::{fs, io::Write};
use tempfile::NamedTempFile;

// Bring the base64::Engine trait into scope so .decode() works.
use base64::Engine as _;

// ---- helpers ---------------------------------------------------------------

/// Return true if ANY contiguous chunk of length `k` from `plain`
/// appears verbatim anywhere in `blob`.
fn contains_any_plain_chunk(plain: &[u8], blob: &[u8], k: usize) -> bool {
    if k == 0 || plain.len() < k || blob.len() < k {
        return false;
    }
    for i in 0..=plain.len() - k {
        let chunk = &plain[i..i + k];
        if blob.windows(k).any(|w| w == chunk) {
            return true;
        }
    }
    false
}

/// Decode ASCII-Armor if present; otherwise return the bytes unchanged.
fn maybe_dearmor(bytes: &[u8]) -> Vec<u8> {
    if looks_armored(bytes) {
        dearmor_compat(bytes)
    } else {
        bytes.to_vec()
    }
}

/// Minimal compatible ASCII-Armor decoder for tests (no library internals).
fn dearmor_compat(data: &[u8]) -> Vec<u8> {
    const BEGIN: &str = "-----BEGIN ENCFILE-----";
    const END: &str = "-----END ENCFILE-----";
    let s = std::str::from_utf8(data).expect("armor is valid utf8");
    let s = s.trim();
    let body = s
        .strip_prefix(BEGIN)
        .and_then(|x| x.strip_suffix(END))
        .expect("malformed armor");
    let body = body.trim_matches(&['\r', '\n', ' '][..]).trim();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .expect("armor body must base64-decode")
}

/// Split binary ciphertext into (full_binary, payload_offset).
/// Layout: [4-byte little-endian header length] [CBOR header bytes...] [payload...]
fn split_binary_and_payload(cipher_bin: &[u8]) -> (Vec<u8>, usize) {
    assert!(cipher_bin.len() >= 4, "too short");
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&cipher_bin[0..4]);
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    assert!(
        cipher_bin.len() >= 4 + header_len,
        "incomplete header: {} > {}",
        header_len,
        cipher_bin.len().saturating_sub(4)
    );
    (cipher_bin.to_vec(), 4 + header_len)
}

fn common_opts(
    alg: AeadAlg,
    armor: bool,
    stream: bool,
    chunk_size: Option<usize>,
) -> EncryptOptions {
    let mut o = EncryptOptions {
        alg,
        armor,
        ..Default::default()
    };
    // Speed up tests: use lightweight Argon2id parameters
    o.kdf = KdfAlg::Argon2id;
    o.kdf_params = KdfParams {
        t_cost: 1,
        mem_kib: 4 * 1024,
        parallelism: 1,
    };
    o.stream = stream;
    if let Some(cs) = chunk_size {
        o.chunk_size = cs;
    }
    o.force = true;
    o
}

// A couple of small deterministic tests for debugging/fail-fast.
#[test]
fn bytes_no_plain_chunks_smoke() {
    let data = b"The quick brown fox jumps over the lazy dog".to_vec();
    let pw = SecretString::new("pw".into());
    let opts = EncryptOptions {
        armor: false,
        ..Default::default()
    };
    let ct = encrypt_bytes(&data, pw, &opts).unwrap();
    assert!(!contains_any_plain_chunk(&data, &ct, 16));
}

// ---- 1) Naive: check entire ciphertext (may include header/armor) -----------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,                 // fewer cases for file I/O
        max_shrink_time: 0,        // avoid long shrinking
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_naive_bytes_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..2048),
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, false, None);
        let pw = SecretString::new("pw".into());

        let ct = encrypt_bytes(&data, pw.clone(), &opts).expect("encrypt ok");

        prop_assert!(!contains_any_plain_chunk(&data, &ct, k));
    }

    #[test]
    fn prop_naive_file_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..8192), // cap at 8 KiB
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, false, None); // non-streaming
        let pw = SecretString::new("pw".into());

        let mut infile = NamedTempFile::new().expect("temp in");
        std::io::Write::write_all(&mut infile, &data).unwrap();

        let out = encrypt_file(infile.path(), None, pw, opts).expect("encrypt ok");
        let ct_file = std::fs::read(&out).expect("read ct");

        prop_assert!(!contains_any_plain_chunk(&data, &ct_file, k));
    }
}

// ---- 2) After de-armor: decode ASCII-Armor to binary, then check -----------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        max_shrink_time: 0,
        .. ProptestConfig::default()
    })]


    #[test]
    fn prop_dearmored_bytes_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..2048),
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, false, None);
        let pw = SecretString::new("pw".into());

        let ct = encrypt_bytes(&data, pw, &opts).expect("encrypt ok");
        let bin = maybe_dearmor(&ct);

        prop_assert!(!contains_any_plain_chunk(&data, &bin, k));
    }

    #[test]
    fn prop_dearmored_file_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..8192),
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, false, None);
        let pw = SecretString::new("pw".into());

        let mut infile = NamedTempFile::new().expect("temp in");
        std::io::Write::write_all(&mut infile, &data).unwrap();

        let out = encrypt_file(infile.path(), None, pw, opts).expect("encrypt ok");
        let raw = std::fs::read(&out).expect("read ct");
        let bin = maybe_dearmor(&raw);

        prop_assert!(!contains_any_plain_chunk(&data, &bin, k));
    }
}

// ---- 3) Payload-only: skip header, check only actual ciphertext payload -----

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        max_shrink_time: 0,
        .. ProptestConfig::default()
    })]


    #[test]
    fn prop_payload_only_bytes_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..2048),
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, false, None);
        let pw = SecretString::new("pw".into());

        let ct = encrypt_bytes(&data, pw, &opts).expect("encrypt ok");
        let bin = maybe_dearmor(&ct);
        let (bin_ct, payload_start) = split_binary_and_payload(&bin);
        let payload = &bin_ct[payload_start..];

        prop_assert!(!contains_any_plain_chunk(&data, payload, k));
    }

 #[test]
    fn prop_payload_only_file_no_plain_chunks(
        data in proptest::collection::vec(any::<u8>(), 16..16384), // cap at 16 KiB
        use_aes in any::<bool>(),
        armor in any::<bool>(),
        stream in any::<bool>(),
        cs in prop_oneof![Just(512usize), Just(1024), Just(4096)], // smaller chunks
        k in prop_oneof![Just(12usize), Just(16), Just(24), Just(32)]
    ) {
        let alg = if use_aes { AeadAlg::Aes256GcmSiv } else { AeadAlg::XChaCha20Poly1305 };
        let opts = common_opts(alg, armor, stream, Some(cs));
        let pw = SecretString::new("pw".into());

        let mut infile = NamedTempFile::new().expect("temp in");
        std::io::Write::write_all(&mut infile, &data).unwrap();

        let out = if stream {
            encrypt_file_streaming(infile.path(), None, pw, opts).expect("encrypt ok")
        } else {
            encrypt_file(infile.path(), None, pw, opts).expect("encrypt ok")
        };

        let raw = std::fs::read(&out).expect("read ct");
        let bin = maybe_dearmor(&raw);
        let (bin_ct, payload_start) = split_binary_and_payload(&bin);
        let payload = &bin_ct[payload_start..];

        prop_assert!(!contains_any_plain_chunk(&data, payload, k));
    }
}

// ---- smoke test: both algorithms and both armor modes ----------------------

#[test]
fn smoke_payload_only_covering_algorithms_and_armor() {
    use std::io::Write;

    let data = b"The quick brown fox jumps over the lazy dog".to_vec();
    let pw = secrecy::SecretString::new("pw".into());

    for &alg in &[
        enc_file::AeadAlg::XChaCha20Poly1305,
        enc_file::AeadAlg::Aes256GcmSiv,
    ] {
        for &armor in &[false, true] {
            // --- Bytes API (stream MUST be false for encrypt_bytes) ---
            let mut opts = enc_file::EncryptOptions::default();
            opts.alg = alg;
            opts.armor = armor;
            opts.stream = false; // <- important: encrypt_bytes rejects stream=true
            // speed up KDF in this test only
            opts.kdf = enc_file::KdfAlg::Argon2id;
            opts.kdf_params = enc_file::KdfParams {
                t_cost: 1,
                mem_kib: 4 * 1024,
                parallelism: 1,
            };
            opts.force = true;

            let ct = enc_file::encrypt_bytes(&data, pw.clone(), &opts).unwrap();
            let bin = if enc_file::looks_armored(&ct) {
                // minimal de-armor for tests
                use base64::Engine as _;
                const BEGIN: &str = "-----BEGIN ENCFILE-----";
                const END: &str = "-----END ENCFILE-----";
                let s = std::str::from_utf8(&ct).unwrap().trim();
                let body = s
                    .strip_prefix(BEGIN)
                    .and_then(|x| x.strip_suffix(END))
                    .unwrap();
                let body = body.trim_matches(&['\r', '\n', ' '][..]).trim();
                base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .unwrap()
            } else {
                ct.clone()
            };
            let (bin_ct, payload_start) = {
                assert!(bin.len() >= 4);
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bin[0..4]);
                let header_len = u32::from_le_bytes(len_bytes) as usize;
                assert!(bin.len() >= 4 + header_len);
                (bin, 4 + header_len)
            };
            let payload = &bin_ct[payload_start..];
            assert!(
                !contains_any_plain_chunk(&data, payload, 16),
                "Plaintext chunk found in payload (bytes API) for alg={:?}, armor={}",
                alg,
                armor
            );

            // --- File API (streaming) ---
            let mut infile = tempfile::NamedTempFile::new().unwrap();
            infile.write_all(&data).unwrap();

            let mut fopts = enc_file::EncryptOptions::default();
            fopts.alg = alg;
            fopts.armor = armor;
            fopts.stream = true;
            fopts.chunk_size = 1024; // smaller chunk for speed
            // same fast KDF for the test
            fopts.kdf = enc_file::KdfAlg::Argon2id;
            fopts.kdf_params = enc_file::KdfParams {
                t_cost: 1,
                mem_kib: 4 * 1024,
                parallelism: 1,
            };
            fopts.force = true;

            let out =
                enc_file::encrypt_file_streaming(infile.path(), None, pw.clone(), fopts).unwrap();
            let raw = std::fs::read(out).unwrap();
            let bin = if enc_file::looks_armored(&raw) {
                use base64::Engine as _;
                const BEGIN: &str = "-----BEGIN ENCFILE-----";
                const END: &str = "-----END ENCFILE-----";
                let s = std::str::from_utf8(&raw).unwrap().trim();
                let body = s
                    .strip_prefix(BEGIN)
                    .and_then(|x| x.strip_suffix(END))
                    .unwrap();
                let body = body.trim_matches(&['\r', '\n', ' '][..]).trim();
                base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .unwrap()
            } else {
                raw
            };
            let (bin_ct, payload_start) = {
                assert!(bin.len() >= 4);
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bin[0..4]);
                let header_len = u32::from_le_bytes(len_bytes) as usize;
                assert!(bin.len() >= 4 + header_len);
                (bin, 4 + header_len)
            };
            let payload = &bin_ct[payload_start..];
            assert!(
                !contains_any_plain_chunk(&data, payload, 16),
                "Plaintext chunk found in payload (file API) for alg={:?}, armor={}",
                alg,
                armor
            );
        }
    }
}

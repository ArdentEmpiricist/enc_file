use assert_fs::prelude::*;
use secrecy::SecretString;
use std::fs;

use enc_file::{AeadAlg, EncFileError, EncryptOptions, decrypt_file, encrypt_file_streaming};

/// Build a small streaming ciphertext with the chosen algorithm
fn make_stream_ct(
    alg: AeadAlg,
) -> (
    assert_fs::TempDir,
    std::path::PathBuf,
    SecretString,
    Vec<u8>,
) {
    let td = assert_fs::TempDir::new().unwrap();
    let pw = SecretString::new("pw".to_string().into());
    let input = td.child("in.bin");
    input.write_binary(b"some streaming input").unwrap();

    let ct_path = td.child("ct.enc");
    let opts = EncryptOptions {
        alg,
        stream: true,
        chunk_size: 65536,
        ..Default::default()
    };
    let out = encrypt_file_streaming(input.path(), Some(ct_path.path()), pw.clone(), opts).unwrap();
    let bytes = fs::read(&out).unwrap();
    (td, out, pw, bytes)
}

fn tamper_chunk_size(file_bytes: Vec<u8>, new_chunk: u32) -> Vec<u8> {
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    // layout: [4 bytes LE header_len][header_bytes][ciphertext...]
    assert!(file_bytes.len() >= 4);
    let mut len_le = [0u8; 4];
    len_le.copy_from_slice(&file_bytes[..4]);
    let header_len = u32::from_le_bytes(len_le) as usize;

    let start = 4;
    let end = 4 + header_len;

    // Parse header as generic CBOR value
    let mut header_val: Value = serde_cbor::from_slice(&file_bytes[start..end]).unwrap();

    // header: Map(Value -> Value) with text keys like "stream", "chunk_size"
    if let Value::Map(ref mut top) = header_val {
        let stream_key = Value::Text("stream".to_string());

        // Ensure "stream" exists and is a map
        let stream_val = top
            .entry(stream_key)
            .or_insert_with(|| Value::Map(BTreeMap::new()));

        if let Value::Map(stream_map) = stream_val {
            // Set/overwrite "chunk_size"
            let cs_key = Value::Text("chunk_size".to_string());
            stream_map.insert(cs_key, Value::Integer(i128::from(new_chunk)));
        } else {
            panic!("header.stream is not a CBOR map");
        }
    } else {
        panic!("header is not a CBOR map");
    }

    // Re-encode header and rebuild the file
    let new_header = serde_cbor::to_vec(&header_val).unwrap();
    let mut rebuilt = Vec::with_capacity(4 + new_header.len() + (file_bytes.len() - end));
    rebuilt.extend_from_slice(&(new_header.len() as u32).to_le_bytes());
    rebuilt.extend_from_slice(&new_header);
    rebuilt.extend_from_slice(&file_bytes[end..]); // ciphertext unchanged
    rebuilt
}

#[test]
fn dec_rejects_zero_chunk_size_in_header_for_both_algs() {
    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv] {
        let (td, _ct_path, pw, bytes) = make_stream_ct(alg);
        let tampered = tamper_chunk_size(bytes, 0); // invalid per validator

        // Write tampered file
        let bad = td.child("bad.enc");
        bad.write_binary(&tampered).unwrap();

        // Decrypt should fail with Invalid
        let out = td.child("out.bin");
        let res = decrypt_file(bad.path(), Some(out.path()), pw.clone());
        match res {
            Err(EncFileError::Invalid(msg)) => {
                assert!(
                    msg.contains("chunk_size"),
                    "unexpected Invalid message: {msg}"
                );
            }
            other => panic!("expected Invalid for zero chunk_size, got: {:?}", other),
        }

        td.close().ok();
    }
}

#[test]
fn dec_rejects_too_large_chunk_size_in_header_for_both_algs() {
    const TAG: u32 = 16;
    let too_big = (u32::MAX - TAG) + 1;

    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256GcmSiv] {
        let (td, _ct_path, pw, bytes) = make_stream_ct(alg);
        let tampered = tamper_chunk_size(bytes, too_big); // invalid per validator

        let bad = td.child("bad2.enc");
        bad.write_binary(&tampered).unwrap();

        let out = td.child("out2.bin");
        let res = decrypt_file(bad.path(), Some(out.path()), pw.clone());
        match res {
            Err(EncFileError::Invalid(msg)) => {
                assert!(
                    msg.contains("chunk_size") || msg.contains("32-bit"),
                    "unexpected Invalid message: {msg}"
                );
            }
            other => panic!(
                "expected Invalid for oversized chunk_size, got: {:?}",
                other
            ),
        }

        td.close().ok();
    }
}

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
    use ciborium::Value;

    // layout: [4 bytes LE header_len][header_bytes][ciphertext...]
    assert!(file_bytes.len() >= 4);
    let mut len_le = [0u8; 4];
    len_le.copy_from_slice(&file_bytes[..4]);
    let header_len = u32::from_le_bytes(len_le) as usize;

    let start = 4;
    let end = 4 + header_len;

    // Parse header as generic CBOR value
    let mut header_val: Value = ciborium::de::from_reader(&file_bytes[start..end]).unwrap();

    // header: Map(Value -> Value) with text keys like "stream", "chunk_size"
    if let Value::Map(ref mut top) = header_val {
        let stream_key = Value::Text("stream".to_string());

        // Find or create "stream" entry
        let mut stream_found = false;
        for (key, value) in top.iter_mut() {
            if *key == stream_key {
                if let Value::Map(stream_map) = value {
                    // Set/overwrite "chunk_size"
                    let cs_key = Value::Text("chunk_size".to_string());
                    let mut chunk_size_found = false;
                    for (sk, sv) in stream_map.iter_mut() {
                        if *sk == cs_key {
                            *sv = Value::Integer((new_chunk as u32).into());
                            chunk_size_found = true;
                            break;
                        }
                    }
                    if !chunk_size_found {
                            *sv = Value::Integer(new_chunk.into());
                            chunk_size_found = true;
                            break;
                        }
                    }
                    if !chunk_size_found {
                        stream_map.push((cs_key, Value::Integer(new_chunk.into())));
                    }
                    stream_found = true;
                    break;
                } else {
                    panic!("header.stream is not a CBOR map");
                }
            }
        }
        
        if !stream_found {
            // Create new stream entry
            let stream_map = vec![(
                Value::Text("chunk_size".to_string()),
                Value::Integer(new_chunk.into())
            )];
            top.push((stream_key, Value::Map(stream_map)));
        }
    } else {
        panic!("header is not a CBOR map");
    }

    // Re-encode header and rebuild the file
    let mut new_header = Vec::new();
    ciborium::ser::into_writer(&header_val, &mut new_header).unwrap();
    let mut rebuilt = Vec::with_capacity(4 + new_header.len() + (file_bytes.len() - end));
    rebuilt.extend_from_slice(&(new_header.len() as u32).to_le_bytes());
    rebuilt.extend_from_slice(&new_header);
    rebuilt.extend_from_slice(&file_bytes[end..]); // ciphertext unchanged
    rebuilt
}

fn msg_contains_any(msg: &str, needles: &[&str]) -> bool {
    needles.iter().any(|s| msg.contains(s))
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
                // Accept multiple valid phrasings from different implementations
                let ok = msg_contains_any(
                    &msg,
                    &[
                        "chunk_size",     // underscore form
                        "chunk size",     // space form
                        "must be > 0",    // explicit lower bound
                        "cannot be zero", // alternate phrasing
                        "zero",           // generic zero mention
                    ],
                );
                assert!(ok, "unexpected Invalid message: {msg}");
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
                // Accept both underscore/space and explicit 32-bit framing hints
                let ok = msg_contains_any(
                    &msg,
                    &[
                        "chunk_size",           // underscore form
                        "chunk size",           // space form
                        "32-bit",               // framing width
                        "too large for 32-bit", // explicit phrasing
                        "too large for frame",  // alternate
                        "frame format",         // generic framing mention
                    ],
                );
                assert!(ok, "unexpected Invalid message: {msg}");
            }
            other => panic!(
                "expected Invalid for oversized chunk_size, got: {:?}",
                other
            ),
        }

        td.close().ok();
    }
}

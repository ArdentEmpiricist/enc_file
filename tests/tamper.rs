use enc_file::{decrypt_bytes, encrypt_bytes, AeadAlg, EncFileError, EncryptOptions};
use secrecy::SecretString;

/// Flip one byte in the ciphertext body and expect Auth failure.
#[test]
fn tamper_ciphertext_fails() {
    let pw = SecretString::new("pw".into());
    let opts = EncryptOptions {
        alg: AeadAlg::XChaCha20Poly1305,
        ..Default::default()
    };
    let msg = b"message to protect";

    let mut ct = encrypt_bytes(msg, pw.clone(), &opts).unwrap();
    // Find a byte after the header (don’t assume header length; just flip near the end).
    if let Some(last) = ct.last_mut() {
        *last ^= 0x01;
    }
    let res = decrypt_bytes(&ct, pw);
    assert!(matches!(res, Err(EncFileError::Crypto)));
}

/// Corrupt the header (first few bytes) and expect parse or crypto error.
#[test]
fn tamper_header_fails() {
    let pw = SecretString::new("pw".into());
    let opts = EncryptOptions {
        alg: AeadAlg::Aes256GcmSiv,
        ..Default::default()
    };
    let msg = b"header tamper";

    let mut ct = encrypt_bytes(msg, pw.clone(), &opts).unwrap();
    // Flip something at the beginning—this should break header magic / version / cbor.
    for b in ct.iter_mut().take(4) {
        *b ^= 0xFF;
    }
    let res = decrypt_bytes(&ct, pw);
    assert!(res.is_err(), "tampered header should fail");
}

/// Wrong password must fail even if ciphertext is intact.
#[test]
fn wrong_password_still_fails() {
    let pw = SecretString::new("right".into());
    let bad = SecretString::new("wrong".into());
    let opts = EncryptOptions::default();
    let msg = b"not so secret";

    let ct = encrypt_bytes(msg, pw, &opts).unwrap();
    let res = decrypt_bytes(&ct, bad);
    assert!(matches!(res, Err(EncFileError::Crypto)));
}

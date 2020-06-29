# Enc-File
Encrypt / decrypt files or calculate the HASH from the command line. Written in Rust without unsafe code. Warning: Don't use for anything important, use VeraCrypt or similar instead.

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Breaking change in Version 0.3: Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Changed to keymap to work with several keys conveniently. You can import your old keys, using "Add key" -> "manually".

Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.

Encrypted files are (and have to be) stored as .crpt.

Both encrypt and decrypt override existing files!

# Examples

```rust
use enc_file::{encrypt_chacha, decrypt_chacha};
let text = b"This a test";
let key: &str = "an example very very secret key.";
let text_vec = text.to_vec();
let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
//let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt 
assert_ne!(&ciphertext, &text);
let plaintext = decrypt_chacha(ciphertext, key).unwrap();
assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
```

Issues and feedback are highly appreciated. 

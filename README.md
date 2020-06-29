# Enc-File
Encrypt / decrypt files or calculate the HASH from the command line. Written in Rust without use of unsafe code. 
**Warning: Don't use for anything important, use VeraCrypt or similar instead.**

## Main menu:
```
Please enter the corresponding number to continue:
1 Add new key
2 Remove key
3 Encrypt file using ChaCha20Poly1305
4 Decrypt file using ChaCha20Poly1305
5 Encrypt file using AES256-GCM-SIV
6 Decrypt file using AES256-GCM-SIV
7 Calculate Hash
```

*Option to generate a new key.file provided at first run or if no key file is detected. Keyfile needs to reside in program directory.*

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Breaking change in Version 0.3: Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Changed to keymap to work with several keys conveniently. You can import your old keys, using "Add key" -> "manually".

Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.

Encrypted files are (and have to be) stored as .crpt.

Both encrypt and decrypt override existing files!

## Examples
Encrypt/decrypt using XChaCha20Poly1305 and random nonce
```rust
use enc_file::{encrypt_chacha, decrypt_chacha};

let text = b"This a test"; //Plaintext to encrypt
let key: &str = "an example very very secret key."; //Key will normally be chosen from keymap and provided to the encrypt_chacha() function
let text_vec = text.to_vec(); //Convert text to Vec<u8>

//Ciphertext stores the len() of encrypted content, the nonce and the actual ciphertext using bincode
let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
//let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt 
assert_ne!(&ciphertext, &text); //Check that plaintext != ciphertext

let plaintext = decrypt_chacha(ciphertext, key).unwrap(); //Decrypt ciphertext to plaintext
assert_eq!(format!("{:?}", text), format!("{:?}", plaintext)); //Check that text == plaintext
```


Calculate Blake3 Hash
```rust
use enc_file::{get_blake3_hash};

let test = b"Calculating the BLAKE3 Hash of this text";
let test_vec = test.to_vec(); //Convert text to Vec<u8>
let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
let hash2 = get_blake3_hash(test_vec).unwrap();
assert_eq!(hash1, hash2); //Make sure hash1 == hash2
```

## To do:
- [x] Add encrypted map on harddrive to use several keys
- [x] Add main menu to guide through the process
- [ ] Enable command-line arguments
- [ ] Add option to securely delete files 

**Issues and feedback are highly appreciated.** 

# Enc_File

[![Rust](https://github.com/LazyEmpiricist/enc_file/workflows/Rust/badge.svg?branch=main)](https://github.com/LazyEmpiricist/enc_file)
[![Crates.io](https://img.shields.io/crates/v/enc_file)](https://crates.io/crates/enc_file)
[![Documentation](https://docs.rs/enc_file/badge.svg)](https://docs.rs/enc_file/)
[![Crates.io](https://img.shields.io/crates/l/enc_file)](https://github.com/LazyEmpiricist/enc_file/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/d/enc_file?color=darkblue)](https://crates.io/crates/enc_file)

Encrypt / decrypt files or calculate the HASH from the command line. Written in Rust without use of unsafe code. 

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-256-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption/decryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3), SHA2-256 / SHA2-512 (https://docs.rs/sha2) oder SHA3-256 / SHA3-512 (https://docs.rs/sha3) for hashing.

XChaCha20Poly1305 and AES256-GCM-SIV offer higher protection against (accidental) nonce reuse as compared to ChaCha20Poly1305 or AES-GCM.

Encrypted files are (and have to be) stored as .crpt.

Both encrypt and decrypt override existing files!

**Panics** at errors making safe execution impossible but functions mostly return results.  

**Installation:** Use cargo install enc_file or clone the repository and build from source.

**Warning: Don't use for anything important, use VeraCrypt or similar instead.**

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

## Usage:
### Main menu (if started without any command line arguments)
```
Please enter the corresponding number to continue:
1 Add new key
2 Remove key
3 Encrypt file using XChaCha20Poly1305
4 Decrypt file using XChaCha20Poly1305
5 Encrypt file using AES-256-GCM-SIV
6 Decrypt file using AES-256-GCM-SIV
7 Calculate Hash
```

*Option to generate a new key.file provided at first run or if no keyfile is detected. Keyfile needs to reside in program directory.*

### Directly calculate hash
Use 
```enc_file hash file_name``` to calculate BLAKE3-Hash,
```enc_file hash_sha2_256 file_name``` to calculate SHA2-256-Hash,
```enc_file hash_sha2_512 file_name``` to calculate SHA2-512-Hash,
```enc_file hash_sha3_256 file_name``` to calculate SHA3-256-Hash,
```enc_file hash_sha3_512 file_name``` to calculate SHA3-512-Hash.

Example: ```enc_file hash ./cargo.toml``` -> ```Hash(65c3342975adeb00ec05dcfab6ccb6af877d3f996957742ec6365541546812e4)```

## Breaking changes:
*Breaking change in Version 0.3:* Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Change to keymap to conveniently work with several keys. You can import your old keys using "Add key" -> "manually".

*Breaking change in Version 0.2:* Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.

## Examples
Encrypt/decrypt using XChaCha20Poly1305 and random nonce
```rust
use enc_file::{encrypt_chacha, decrypt_chacha};

let text = b"This is a test"; //Plaintext to encrypt
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
let test2 = b"Calculating the BLAKE3 Hash of this text."; //"." added at the end
let test2_vec = test2.to_vec();
let hash3 = get_blake3_hash(test2_vec).unwrap();
assert_ne!(hash1, hash3); //check that the added "." changes the hash
```

## To do:
- [x] Add encrypted map on harddrive to use several keys
- [x] Add main menu to guide through the process
- [x] Enable command-line arguments to calculate hash
- [ ] Perhaps: Enable command-line arguments for encrpytion/decryption

**Issues and feedback are highly appreciated.** 

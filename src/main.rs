//! # Enc_File
//!
//! Encrypt / decrypt files or calculate hash from the command line.
//! Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
//!
//! Breaking change in Version 0.3: Changed input of some functions. To encrypt/decrypt and hash use e.g. "encrypt_chacha(readfile(example.file).unwrap(), key).unwrap()". Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" -> "manually".
//!
//! Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//!
//! Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//!
//! Encrypted files are (and have to be) stored as .crpt.
//!
//! Panics at errors making execution impossible.  
//!
//! Can be used as library and a binary target. Install via cargo install enc_file
//! # Examples
//!
//! ```
//! use enc_file::{encrypt_chacha, decrypt_chacha, read_file};
//!
//! //Plaintext to encrypt
//! let text = b"This a test";
//! //Provide key. Key will normally be chosen from keymap and provided to the encrypt_chacha() function
//! let key: &str = "an example very very secret key.";
//! //Convert text to Vec<u8>
//! let text_vec = text.to_vec();
//!
//! //Encrypt text
//! //Ciphertext stores the len() of encrypted content, the nonce and the actual ciphertext using bincode
//! let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
//! //let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
//! //Check that plaintext != ciphertext
//! assert_ne!(&ciphertext, &text);
//!
//! //Decrypt ciphertext to plaintext
//! let plaintext = decrypt_chacha(ciphertext, key).unwrap();
//! //Check that text == plaintext
//! assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
//! ```
//!
//! ```
//! use enc_file::{get_blake3_hash};
//! 
//! let test = b"Calculating the BLAKE3 Hash of this text";
//! let test_vec = test.to_vec(); //Convert text to Vec<u8>
//! let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
//! let hash2 = get_blake3_hash(test_vec).unwrap();
//! assert_eq!(hash1, hash2); //Make sure hash1 == hash2
//! ```
//!
//! See https://github.com/LazyEmpiricist/enc_file
//!

// Warning: Don't use for anything important! This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.
//
// Breaking change in Version 0.3: Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" and choose "manually".
//
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Generate a new key.file on first run (you can also manually add keys).
//
// Encrypting "example.file" will create a new (encrypted) file "example.file.crpt" in the same directory.
//
// Decrypting "example.file.crpt" will create a new (decrypted) file "example.file" in the same directory.
//
// Warning: Both encrypt and decrypt override existing files!
//
//
// # Examples
//
// Encrypt/decrypt using XChaCha20Poly1305 and random nonce
// ```
// use enc_file::{encrypt_chacha, decrypt_chacha, read_file};
//
// //Plaintext to encrypt
// let text = b"This a test";
// //Provide key. Key will normally be chosen from keymap and provided to the encrypt_chacha() function
// let key: &str = "an example very very secret key.";
// //Convert text to Vec<u8>
// let text_vec = text.to_vec();
//
// //Encrypt text
// let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
// //let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
// //Check that plaintext != ciphertext
// assert_ne!(&ciphertext, &text);
//
// //Decrypt ciphertext to plaintext
// let plaintext = decrypt_chacha(ciphertext, key).unwrap();
// //Check that text == plaintext
// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
// ```
//
// Calculate Blake3 Hash
// ```
// use enc_file::{get_blake3_hash};
//
// let test = b"Calculating the BLAKE3 Hash of this text";
// let test_vec = test.to_vec(); //Convert text to Vec<u8>
// let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
// let hash2 = get_blake3_hash(test_vec).unwrap();
// assert_eq!(hash1, hash2); //Make sure hash1 == hash2
// ```


use enc_file::{
    add_key, choose_hashing_function, create_new_keyfile, decrypt_file, encrypt_file,
    get_input_string, read_keyfile, remove_key,
};

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Please enter the corresponding number to continue:\n1 Add new key\n2 Remove key\n3 Encrypt file using ChaCha20Poly1305\n4 Decrypt file using ChaCha20Poly1305\n5 Encrypt file using AES256-GCM-SIV\n6 Decrypt file using AES256-GCM-SIV\n7 Calculate Hash");
    //Getting user input
    let answer = get_input_string()?;
    // Creating a Vec with choices needing a password to compare to user input
    let requiring_pw = vec![
        "1".to_string(),
        "2".to_string(),
        "3".to_string(),
        "4".to_string(),
        "5".to_string(),
        "6".to_string(),
    ];
    //check if the operation needs access to the keymap, requiring a password. Hashing can be done without a password.
    if requiring_pw.contains(&answer) {
        //All functions in this if-block require a password
        //Check if there is a key.file in the directory
        let (password, keymap_plaintext, new) = if Path::new("./key.file").exists() == false {
            //No key.file found. Ask if a new one should be created.
            create_new_keyfile()?
        } else {
            //key.file found. Reading and decrypting content
            read_keyfile()?
        };
        if answer == "1" {
            //if user just created a new key, no need to ask again for a second key
            if new == false {
                //Adding a new key to keymap
                add_key(keymap_plaintext, password)?;
            } else {
            }
        } else if answer == "2" {
            //removing a key from keymap
            remove_key(keymap_plaintext, password)?;
        } else if answer == "3" {
            //Encrypt file using ChaCha20Poly1305 with choosen key
            encrypt_file(keymap_plaintext, "chacha")?;
        } else if answer == "4" {
            //Decrypt file ChaCha20Poly1305 with choosen key
            decrypt_file(keymap_plaintext, "chacha")?;
        } else if answer == "5" {
            //Encrypt file using AES256-GCM-SIV with choosen key
            encrypt_file(keymap_plaintext, "aes")?;
        } else if answer == "6" {
            //Decrypt file using AES256-GCM-SIV with choosen key
            decrypt_file(keymap_plaintext, "aes")?;
        }
    //the following function don't need a password (as they don't access keymap)
    } else if answer == "7" {
        //Get Blake3, SHA256 or SHA512 HASH of file
        choose_hashing_function()?;
    } else {
        //User did not a valid number (between 1 and 7)
        println!("Please enter a valid choice")
    }

    Ok(())
}

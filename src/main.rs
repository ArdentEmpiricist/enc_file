//! # Enc_File
//!
//! `Enc_File` is a simple tool to encrypt / decrypt files and to calculate the BLAKE3, SHA2 256 and 512 hashes. Warning: Don't use for anything important, use VeraCrypt or similar instead.
//!
//! It's a binary target. Install via cargo install enc_file
//!
//! See https://github.com/LazyEmpiricist/enc_file
//!
//! # Examples
//!
//! ```
//! use ::enc_file::{create_key, decrypt_file, encrypt_file, read_file, save_file};
//! use serde::{Deserialize, Serialize};
//! use std::env;
//! use std::str::from_utf8;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let args: Vec<String> = env::args().collect();
//! //args[0] will be the filename or the cargo command!
//! if args.len() >= 2 {
//!    let operation = &args[1];
//!    println!("Operation: {}", &operation);
//!    if operation == "encrypt" && args.len() == 4 {
//!        let filename = &args[2];
//!        let keyfile = &args[3];
//!        println!("File {}", &filename);
//!        println!("Keyfile: {}", &keyfile);
//!        let key = read_file(keyfile)?;
//!        let key: &str = from_utf8(&key)?;
//!        let content = read_file(&filename)?;
//!        let ciphertext: Vec<u8> = encrypt_file_chacha(content, &key)?;
//!        let new_filename: String = filename.to_owned() + ".crypt";
//!        //println!("Ciphertext: {:?}", &ciphertext);
//!        save_file(ciphertext, &new_filename)?;
//!        println!("Successfully enrypted file to {:?}", &new_filename);
//!    } else if operation == "decrypt" && args.len() == 4 {
//!        let filename = &args[2];
//!        let keyfile = &args[3];
//!        println!("File {}", &filename);
//!        println!("Keyfile: {}", &keyfile);
//!        let key = read_file(keyfile)?;
//!        let key: &str = from_utf8(&key)?;
//!        let filename_decrypted: &str = &filename[0..filename.find("crypt").unwrap()];
//!        let ciphertext = read_file(filename)?;
//!        //println!("Ciphertext read from file: {:?}", &ciphertext);
//!        //println!("Decrypted");
//!        let plaintext: Vec<u8> = decrypt_file_chacha(ciphertext, &key)?;
//!        save_file(plaintext, filename_decrypted)?;
//!        println!("Successfully decrypted file to {:?}", &filename_decrypted);
//!    } else if operation == "create-key" && args.len() == 3 {
//!        let filename = &args[2];
//!        println!("File {}", &filename);
//!        create_key(&filename)?;
//!        println!("Keyfile {:?} created", &filename);
//!    }
//! } else {
//!    println!(
//!        r#"Use "encrypt filename-to_encrypt filename-keyfile" or "decrypt filename-to_decrypt filename-keyfile" or "create-key filename-keyfile" "#
//!    );
//!    println!(r#"Example: "encrypt text.txt key.file""#);
//! }
//! Ok(())
//! }
//! ```

// Warning: Don't use for anything important! This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.
//
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Either generate a keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile. Key has to be valid utf8.
//
// "cargo run encrypt .example.file .key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.
//
// "cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files!

use enc_file::{
    create_key, decrypt_file_aes, decrypt_file_chacha, encrypt_file_aes, encrypt_file_chacha, get_blake3_hash, get_sha256_hash, get_sha512_hash,
    read_file, save_file,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::str::from_utf8;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Cipher {
    len: u128,
    rand_string: String,
    ciphertext: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    //args[0] will be the filename or the cargo command!
    if args.len() >= 2 {
        let operation = &args[1];
        println!("Operation: {}", &operation);
        if operation == "encrypt" && args.len() == 4 {
            let filename = PathBuf::from(&args[2]);
            let keyfile = PathBuf::from(&args[3]);
            println!("Encrypting File {:?}", &filename);
            println!("With Keyfile: {:?}", &keyfile);
            let key = read_file(&keyfile)?;
            let key: &str = from_utf8(&key)?;
            let content = read_file(&filename)?;
            let ciphertext: Vec<u8> = encrypt_file_chacha(content, &key)?;
            let new_filename: String =
                filename.clone().into_os_string().into_string().unwrap() + r#".crpt"#;
            let new_filename: PathBuf = PathBuf::from(new_filename);
            //println!("Ciphertext: {:?}", &ciphertext);
            save_file(ciphertext, &new_filename)?;
            println!(
                "Successfully enrypted file {:?} to {:?}",
                filename, new_filename
            );
        } if operation == "encrypt_aes" && args.len() == 4 {
            let filename = PathBuf::from(&args[2]);
            let keyfile = PathBuf::from(&args[3]);
            println!("Encrypting File {:?}", &filename);
            println!("With Keyfile: {:?}", &keyfile);
            let key = read_file(&keyfile)?;
            let key: &str = from_utf8(&key)?;
            let content = read_file(&filename)?;
            let ciphertext: Vec<u8> = encrypt_file_aes(content, &key)?;
            let new_filename: String =
                filename.clone().into_os_string().into_string().unwrap() + r#".crpt"#;
            let new_filename: PathBuf = PathBuf::from(new_filename);
            //println!("Ciphertext: {:?}", &ciphertext);
            save_file(ciphertext, &new_filename)?;
            println!(
                "Successfully enrypted file {:?} to {:?}",
                filename, new_filename
            );
        } else if operation == "decrypt" && args.len() == 4 {
            let filename = PathBuf::from(&args[2]);
            let keyfile = PathBuf::from(&args[3]);
            println!("Decrypting File {:?}", &filename);
            println!("With Keyfile: {:?}", &keyfile);
            let key = read_file(&keyfile)?;
            let key: &str = from_utf8(&key)?;
            let filename_two = &filename.clone();
            let filename_decrypted: &str =
                    &filename_two.to_str().unwrap().replace(r#".crpt"#, r#""#);
            let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
            let ciphertext = read_file(&filename)?;
            //println!("Ciphertext read from file: {:?}", &ciphertext);
            //println!("Decrypted");
            let plaintext: Vec<u8> = decrypt_file_chacha(ciphertext, &key)?;
            save_file(plaintext, &filename_decrypted_path)?;
            println!(
                "Successfully decrypted file {:?} to {:?}",
                filename, filename_decrypted
            );
        } else if operation == "decrypt_aes" && args.len() == 4 {
            let filename = PathBuf::from(&args[2]);
            let keyfile = PathBuf::from(&args[3]);
            println!("Decrypting File {:?}", &filename);
            println!("With Keyfile: {:?}", &keyfile);
            let key = read_file(&keyfile)?;
            let key: &str = from_utf8(&key)?;
            let filename_two = &filename.clone();
            let filename_decrypted: &str =
                    &filename_two.to_str().unwrap().replace(r#".crpt"#, r#""#);
            let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
            let ciphertext = read_file(&filename)?;
            //println!("Ciphertext read from file: {:?}", &ciphertext);
            //println!("Decrypted");
            let plaintext: Vec<u8> = decrypt_file_aes(ciphertext, &key)?;
            save_file(plaintext, &filename_decrypted_path)?;
            println!(
                "Successfully decrypted file {:?} to {:?}",
                filename, filename_decrypted
            );
        } else if operation == "create-key" && args.len() == 3 {
            let filename = PathBuf::from(&args[2]);
            println!("Create Keyfile {:?}", filename);
            create_key(&filename)?;
            println!("Keyfile {:?} created", filename);
        } else if operation == "hash" && args.len() == 3 {
            let filename = PathBuf::from(&args[2]);
            let hash = get_blake3_hash(&filename)?;
            println!("File: {:?}. BLAKE3 hash: {:?}", filename, hash);
        } else if operation == "hash_sha256" && args.len() == 3 {
            let filename = PathBuf::from(&args[2]);
            let hash = get_sha256_hash(&filename)?;
            println!("File: {:?}. SHA256 hash: {:?}", filename, hash);
        } else if operation == "hash_sha512" && args.len() == 3 {
            let filename = PathBuf::from(&args[2]);
            let hash = get_sha512_hash(&filename)?;
            println!("File: {:?}. SHA512 hash: {:?}", filename, hash);
        }
    } else {
        println!(
            r#"Use "encrypt filename-to_encrypt filename-keyfile" to encrypt a file using XChaCha20Poly1305 or 
            "encrypt_aes filename-to_encrypt filename-keyfile" to encrypt a file using AES-GCM-SIV or
            "decrypt filename-to_decrypt filename-keyfile" to decrypt a file using XChaCha20Poly1305 or 
            "decrypt_aes filename-to_decrypt filename-keyfile" to decrypt a file using AES-GCM-SIV or
            "create-key filename-keyfile" to create a new random  keyfile or 
            "hash filename" (using BLAKE3) to calculate the BLAKE3 hash for a file or 
            "hash_sha256 filename" to calculate the SHA256 hash for a file or 
            "hash_sha512 filename" ro calculate the SHA512 hash for a file"#
        );
        println!(r#"Example: "encrypt text.txt key.file""#);
    }
    Ok(())
}
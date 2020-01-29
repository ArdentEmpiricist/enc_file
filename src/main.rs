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
//!        let ciphertext: Vec<u8> = encrypt_file(content, &key)?;
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
//!        let plaintext: Vec<u8> = decrypt_file(ciphertext, &key)?;
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
// Uses AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography and bincode (https://docs.rs/bincode) for encoding.
//
// Either generate a keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile. Key has to be valid utf8.
//
// "cargo run encrypt .example.file .key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.
//
// "cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files!

use enc_file::{
    create_key, decrypt_file, encrypt_file, get_blake3_hash, get_sha256_hash, get_sha512_hash,
    read_file, save_file,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::str::from_utf8;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Cipher {
    len: usize,
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
            let filename = &args[2];
            let keyfile = &args[3];
            println!("File {}", &filename);
            println!("Keyfile: {}", &keyfile);
            let key = read_file(keyfile)?;
            let key: &str = from_utf8(&key)?;
            let content = read_file(&filename)?;
            let ciphertext: Vec<u8> = encrypt_file(content, &key)?;
            let new_filename: String = filename.to_owned() + ".crpt";
            //println!("Ciphertext: {:?}", &ciphertext);
            save_file(ciphertext, &new_filename)?;
            println!("Successfully enrypted file to {:?}", &new_filename);
        } else if operation == "decrypt" && args.len() == 4 {
            let filename = &args[2];
            let keyfile = &args[3];
            println!("File {}", &filename);
            println!("Keyfile: {}", &keyfile);
            let key = read_file(keyfile)?;
            let key: &str = from_utf8(&key)?;
            let filename_decrypted: &str = &filename[0..filename.find(".crpt").unwrap()];
            let ciphertext = read_file(filename)?;
            //println!("Ciphertext read from file: {:?}", &ciphertext);
            //println!("Decrypted");
            let plaintext: Vec<u8> = decrypt_file(ciphertext, &key)?;
            save_file(plaintext, filename_decrypted)?;
            println!("Successfully decrypted file to {:?}", &filename_decrypted);
        } else if operation == "create-key" && args.len() == 3 {
            let filename = &args[2];
            println!("File {}", &filename);
            create_key(&filename)?;
            println!("Keyfile {:?} created", &filename);
        } else if operation == "hash" && args.len() == 3 {
            let filename = &args[2];
            let hash = get_blake3_hash(&filename)?;
            println!("File: {}. BLAKE3 hash: {:?}", filename, hash);
        } else if operation == "hash_sha256" && args.len() == 3 {
            let filename = &args[2];
            let hash = get_sha256_hash(&filename)?;
            println!("File: {}. SHA256 hash: {:?}", filename, hash);
        } else if operation == "hash_sha512" && args.len() == 3 {
            let filename = &args[2];
            let hash = get_sha512_hash(&filename)?;
            println!("File: {}. SHA512 hash: {:?}", filename, hash);
        }
    } else {
        println!(
            r#"Use "encrypt filename-to_encrypt filename-keyfile" or "decrypt filename-to_decrypt filename-keyfile" or "create-key filename-keyfile" or "hash filename" (using BLAKE3) or "hash_sha256 filename" or "hash_sha512 filename" "#
        );
        println!(r#"Example: "encrypt text.txt key.file""#);
    }
    Ok(())
}

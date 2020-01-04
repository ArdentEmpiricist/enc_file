//! # Enc_File
//!
//! `Enc_File` is a simple tool to encrypt and decrypt files. Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
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
// Either generate a keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile.
//
// "cargo run encrypt .example.file .key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.
//
// "cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files! aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Cipher {
    len: usize,
    rand_string: String,
    ciphertext: Vec<u8>,
}

/// Reads file from same folder as Vec<u8>. Returns result.
/// # Examples
///
/// ```
/// let path: &str = "test.file";
/// let content_read: Vec<u8> = read_file(&path).unwrap();
/// ```
pub fn read_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)?;
    //println!("{:?}", from_utf8(&buffer)?);
    Ok(buffer)
}

/// Saves file to same folder. Returns result
/// # Examples
///
/// ```
/// let key = read_file(keyfile)?;
/// let key: &str = from_utf8(&key)?;
/// ```
pub fn save_file(data: Vec<u8>, path: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

/// Creates a new key from given charset. Does not use crypto_rand at this time. Returns result.
/// # Examples
///
/// ```
/// let path: &str = "test.file";
/// let content_read: Vec<u8> = read_file(&path).unwrap();
/// ```
pub fn create_key(path: &str) -> std::io::Result<()> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    const KEY_LEN: usize = 32;
    let mut rng = rand::thread_rng();

    let key: String = (0..KEY_LEN)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    let mut file = File::create(path)?;
    file.write_all(&key.as_bytes())?;
    Ok(())
}

/// Encrypts cleartext (Vec<u8>) into ciphertext (Vec<u8>) using provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext = encrypt_file(text_vec, key).unwrap();
/// ```
pub fn encrypt_file(cleartext: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(key);
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(12).collect();
    let nonce = GenericArray::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, cleartext.as_ref())
        .expect("encryption failure!");
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    let encoded: Vec<u8> = bincode::serialize(&ciphertext_to_send).unwrap();
    Ok(encoded)
}

/// Decrypts ciphertext (Vec<u8>) into cleartext (Vec<u8>) using provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let key: &str = "an example very very secret key.";
/// let plaintext = decrypt_file(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_file(enc: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(key);
    let decoded: Cipher = bincode::deserialize(&enc[..]).unwrap();
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string2.as_bytes());
    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext2.as_ref())
        .expect("decryption failure!");
    //println!("{:?}", std::str::from_utf8(&plaintext).unwrap());
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    #[test]
    fn test_save_read_file() {
        let content: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let path: &str = "test.file";
        save_file(content.clone(), &path).unwrap();
        let content_read: Vec<u8> = read_file(&path).unwrap();
        remove_file(&path).unwrap(); //remove file created for this test
        assert_eq!(content, content_read);
    }

    #[test]
    fn test_encryt_decrypt() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let text_vec = text.to_vec();
        let ciphertext = encrypt_file(text_vec, key).unwrap();
        let plaintext = decrypt_file(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }
}

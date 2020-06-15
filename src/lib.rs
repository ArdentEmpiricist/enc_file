//! # Enc_File
//!
//! `Enc_File` is a simple tool to encrypt and decrypt files. Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
//!
//! Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability. 
//!
//! Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//!
//! Encrypted files are (and have to be) stored as .crpt.
//!
//! It's a binary target. Install via cargo install enc_file
//!
//! See https://github.com/LazyEmpiricist/enc_file
//!
//! # Examples
//!
//! ```
//! use enc_file::{
//!   create_key, decrypt_file_aes, decrypt_file_chacha, encrypt_file_aes, encrypt_file_chacha, get_blake3_hash, get_sha256_hash, get_sha512_hash,
//!   read_file, save_file,
//!};
//!use serde::{Deserialize, Serialize};
//!use std::env;
//!use std::path::PathBuf;
//!use std::str::from_utf8;
//!
//!#[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Cipher {
//!    len: usize,
//!    rand_string: String,
//!    ciphertext: Vec<u8>,
//! }
//!    let args: Vec<String> = env::args().collect();
//!    //args[0] will be the filename or the cargo command!
//!    if args.len() >= 2 {
//!        let operation = &args[1];
//!        println!("Operation: {}", &operation);
//!        if operation == "encrypt" && args.len() == 4 {
//!            let filename = PathBuf::from(&args[2]);
//!            let keyfile = PathBuf::from(&args[3]);
//!            println!("Encrypting File {:?}", &filename);
//!            println!("With Keyfile: {:?}", &keyfile);
//!            let key = read_file(&keyfile)?;
//!            let key: &str = from_utf8(&key)?;
//!            let content = read_file(&filename)?;
//!            let ciphertext: Vec<u8> = encrypt_file_chacha(content, &key)?;
//!            let new_filename: String =
//!                filename.clone().into_os_string().into_string().unwrap() + ".crpt";
//!            let new_filename: PathBuf = PathBuf::from(new_filename);
//!            //println!("Ciphertext: {:?}", &ciphertext);
//!            save_file(ciphertext, &new_filename)?;
//!            println!(
//!                "Successfully enrypted file {:?} to {:?}",
//!                filename, new_filename
//!            );
//!        } if operation == "encrypt_aes" && args.len() == 4 {
//!            let filename = PathBuf::from(&args[2]);
//!            let keyfile = PathBuf::from(&args[3]);
//!            println!("Encrypting File {:?}", &filename);
//!            println!("With Keyfile: {:?}", &keyfile);
//!            let key = read_file(&keyfile)?;
//!            let key: &str = from_utf8(&key)?;
//!            let content = read_file(&filename)?;
//!            let ciphertext: Vec<u8> = encrypt_file_aes(content, &key)?;
//!            let new_filename: String =
//!                filename.clone().into_os_string().into_string().unwrap() + ".crpt";
//!            let new_filename: PathBuf = PathBuf::from(new_filename);
//!            //println!("Ciphertext: {:?}", &ciphertext);
//!            save_file(ciphertext, &new_filename)?;
//!            println!(
//!                "Successfully enrypted file {:?} to {:?}",
//!                filename, new_filename
//!            );
//!        } else if operation == "decrypt" && args.len() == 4 {
//!            let filename = PathBuf::from(&args[2]);
//!            let keyfile = PathBuf::from(&args[3]);
//!            println!("Decrypting File {:?}", &filename);
//!            println!("With Keyfile: {:?}", &keyfile);
//!            let key = read_file(&keyfile)?;
//!            let key: &str = from_utf8(&key)?;
//!            let filename_two = &filename.clone();
//!            let filename_decrypted: &str =
//!                    &filename_two.to_str().unwrap().replace("crpt", "plaintext");
//!            let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
//!            let ciphertext = read_file(&filename)?;
//!            //println!("Ciphertext read from file: {:?}", &ciphertext);
//!            //println!("Decrypted");
//!            let plaintext: Vec<u8> = decrypt_file_chacha(ciphertext, &key)?;
//!            save_file(plaintext, &filename_decrypted_path)?;
//!            println!(
//!                "Successfully decrypted file {:?} to {:?}",
//!                filename, filename_decrypted
//!            );
//!        } else if operation == "decrypt_aes" && args.len() == 4 {
//!            let filename = PathBuf::from(&args[2]);
//!            let keyfile = PathBuf::from(&args[3]);
//!            println!("Decrypting File {:?}", &filename);
//!            println!("With Keyfile: {:?}", &keyfile);
//!            let key = read_file(&keyfile)?;
//!            let key: &str = from_utf8(&key)?;
//!            let filename_two = &filename.clone();
//!            let filename_decrypted: &str =
//!                    &filename_two.to_str().unwrap().replace("crpt", "plaintext");
//!            let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
//!            let ciphertext = read_file(&filename)?;
//!            //println!("Ciphertext read from file: {:?}", &ciphertext);
//!            //println!("Decrypted");
//!            let plaintext: Vec<u8> = decrypt_file_aes(ciphertext, &key)?;
//!            save_file(plaintext, &filename_decrypted_path)?;
//!            println!(
//!                "Successfully decrypted file {:?} to {:?}",
//!                filename, filename_decrypted
//!            );
//!        } else if operation == "create-key" && args.len() == 3 {
//!            let filename = PathBuf::from(&args[2]);
//!            println!("Create Keyfile {:?}", filename);
//!            create_key(&filename)?;
//!            println!("Keyfile {:?} created", filename);
//!        } else if operation == "hash" && args.len() == 3 {
//!            let filename = PathBuf::from(&args[2]);
//!            let hash = get_blake3_hash(&filename)?;
//!            println!("File: {:?}. BLAKE3 hash: {:?}", filename, hash);
//!        } else if operation == "hash_sha256" && args.len() == 3 {
//!            let filename = PathBuf::from(&args[2]);
//!            let hash = get_sha256_hash(&filename)?;
//!            println!("File: {:?}. SHA256 hash: {:?}", filename, hash);
//!        } else if operation == "hash_sha512" && args.len() == 3 {
//!            let filename = PathBuf::from(&args[2]);
//!            let hash = get_sha512_hash(&filename)?;
//!            println!("File: {:?}. SHA512 hash: {:?}", filename, hash);
//!        }
//!    } else {
//!        println!(
//!            r#"Use "encrypt filename-to_encrypt filename-keyfile" to encrypt a file using XChaCha20Poly1305 or 
//!            "encrypt_aes filename-to_encrypt filename-keyfile" to encrypt a file using AES-GCM-SIV or
//!            "decrypt filename-to_decrypt filename-keyfile" to decrypt a file using XChaCha20Poly1305 or 
//!            "decrypt_aes filename-to_decrypt filename-keyfile" to decrypt a file using AES-GCM-SIV or
//!            "create-key filename-keyfile" to create a new random  keyfile or 
//!            "hash filename" (using BLAKE3) to calculate the BLAKE3 hash for a file or 
//!            "hash_sha256 filename" to calculate the SHA256 hash for a file or 
//!            "hash_sha512 filename" ro calculate the SHA512 hash for a file"#
//!        );
//!        println!(r#"Example: "encrypt text.txt key.file""#);
//!    }
//!    Ok(())
//!}
//! ```

// Warning: Don't use for anything important! This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.
//
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability. //
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Either generate a keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile.
//
// "cargo run encrypt .example.file .key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.
//
// "cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files! 
//
// Calculate hash using BLAKE3 (argument "hash", recommended), SHA256 (argument "hash_sha256") or SHA512 (argument "hash_sha512")

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

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
pub fn read_file(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut f = File::open(path)?;
    let mut buffer: Vec<u8> = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)?;
    //println!("{:?}", from_utf8(&buffer)?);
    Ok(buffer)
}

/// Saves file to same folder. Returns result
/// # Examples
///
/// ```
/// let new_filename: String = filename.to_owned() + ".crpt";
/// save_file(ciphertext, &new_filename).unwrap();
/// ```
pub fn save_file(data: Vec<u8>, path: &PathBuf) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

/// Creates a new key from given charset. Does not use crypto_rand at this time. Returns result.
/// # Examples
///
/// ```
/// let filename = PathBuf::from("test.file")";
/// create_key(&filename).unwrap();
/// ```
pub fn create_key(path: &PathBuf) -> std::io::Result<()> {
    let key: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect::<String>();

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
/// let ciphertext: Vec<u8> = encrypt_file_aes(text_vec, key).unwrap();
/// ```
pub fn encrypt_file_aes(cleartext: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(&key);
    let rand_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(12)
        .collect::<String>();
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

/// Encrypts cleartext (Vec<u8>) into ciphertext (Vec<u8>) using XChaCha20Poly1305 with provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext: Vec<u8> = encrypt_file_chacha(text_vec, key).unwrap();
/// ```
pub fn encrypt_file_chacha(cleartext: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);
    let rand_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(24)
        .collect::<String>();
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
/// let plaintext: Vec<u8> = decrypt_file_aes(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_file_aes(enc: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(&key);
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

/// Decrypts ciphertext (Vec<u8>) into cleartext (Vec<u8>) using XChaCha20Poly1305 with provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let key: &str = "an example very very secret key.";
/// let plaintext: Vec<u8> = decrypt_file_chacha(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_file_chacha(enc: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);
    let decoded: Cipher = bincode::deserialize(&enc[..])?;
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

/// Get BLAKE3 Hash from file. Returns result.
/// # Examples
///
/// ```
/// let filename = "cargo.toml";
/// let hash1 = get_blake3_hash(&filename).unwrap();
/// let hash2 = get_blake3_hash(&filename).unwrap();
/// println!("File: {}. hash1: {:?}, hash2: {:?}", filename, hash1, hash2);
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_blake3_hash(path: &PathBuf) -> Result<blake3::Hash, Box<dyn std::error::Error>> {
    let data = read_file(&path)?;
    let hash = blake3::hash(&data);
    Ok(hash)
}

/// Get SHA256 Hash from file. Returns result.
/// # Examples
///
/// ```
/// let filename = "cargo.toml";
/// let hash1 = get_sha256_hash(&filename).unwrap();
/// let hash2 = get_sha256_hash(&filename).unwrap();
/// println!("File: {}. hash1: {:?}, hash2: {:?}", filename, hash1, hash2);
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_sha256_hash(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let data = read_file(&path)?;
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Get SHA512 Hash from file. Returns result.
/// # Examples
///
/// ```
/// let filename = "cargo.toml";
/// let hash1 = get_sha512_hash(&filename).unwrap();
/// let hash2 = get_sha512_hash(&filename).unwrap();
/// println!("File: {}. hash1: {:?}, hash2: {:?}", filename, hash1, hash2);
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_sha512_hash(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let data = read_file(&path)?;
    // create a Sha256 object
    let mut hasher = Sha512::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    #[test]
    fn test_save_read_file() {
        let content: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let path: PathBuf = PathBuf::from("test_abcdefg.file");
        save_file(content.clone(), &path).unwrap();
        let content_read: Vec<u8> = read_file(&path).unwrap();
        remove_file(&path).unwrap(); //remove file created for this test
        assert_eq!(content, content_read);
    }

    #[test]
    fn test_encryt_decrypt_aes() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let text_vec = text.to_vec();
        let ciphertext = encrypt_file_aes(text_vec, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_file_aes(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_encryt_decrypt_chacha() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let text_vec = text.to_vec();
        let ciphertext = encrypt_file_chacha(text_vec, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_file_chacha(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_hash_blake3() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_blake3_hash(&filename).unwrap();
        let hash2 = get_blake3_hash(&filename).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sha256() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_sha256_hash(&filename).unwrap();
        let hash2 = get_sha256_hash(&filename).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sha512() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_sha512_hash(&filename).unwrap();
        let hash2 = get_sha512_hash(&filename).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_multiple_random_chacha() {
        use rand::{distributions::Uniform, Rng};
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        let mut i = 1;
        while i < 1000 {
        let key: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect::<String>();
            
        let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
        let ciphertext = encrypt_file_chacha(content.clone(), &key).unwrap();
        assert_ne!(&ciphertext, &content);
        let plaintext = decrypt_file_chacha(ciphertext, &key).unwrap();
        assert_eq!(format!("{:?}", content), format!("{:?}", plaintext));

        i += 1;
        }

    }

    #[test]
    fn test_multiple_random_aes() {
        use rand::{distributions::Uniform, Rng};
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        let mut i = 1;
        while i < 1000 {
        let key: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect::<String>();
            
        let content: Vec<u8> = (0..100).map(|_| rng.sample(&range)).collect();
        let ciphertext = encrypt_file_aes(content.clone(), &key).unwrap();
        assert_ne!(&ciphertext, &content);
        let plaintext = decrypt_file_aes(ciphertext, &key).unwrap();
        assert_eq!(format!("{:?}", content), format!("{:?}", plaintext));

        i += 1;
        }

    }
}
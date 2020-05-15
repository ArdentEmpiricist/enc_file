//! # Enc_File
//!
//! `Enc_File` is a simple tool to encrypt and decrypt files. Warning: This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties. Don't use for anything important, use VeraCrypt or similar instead.
//!
//! Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes - old files can still be used.
//!
//! Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
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
//!    } else if operation == "hash" && args.len() == 3 {
//!         let filename = &args[2];
//!         let hash = get_blake3_hash(&filename)?;
//!         println!("File: {}. BLAKE3 hash: {:?}", filename, hash);
//!         }
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
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
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
use std::io::BufReader;
use std::io::{self, BufRead};
use std::io::{Error, ErrorKind};
use std::path::Path;
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
/// let filename: &str = "test.file";
/// create_key(&filename).unwrap();
/// ```
pub fn create_key(path: &PathBuf) -> std::io::Result<()> {
    let mut number = 100;

    let mut all_keys = String::new();

    while number != 0 {
        let mut key: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect::<String>();

        key.push_str("\n");

        all_keys.push_str(&key);

        number -= 1;
    }
    let mut file = File::create(path)?;
    file.write_all(&all_keys.as_bytes())?;
    Ok(())
}

/// Encrypts cleartext (Vec<u8>) into ciphertext (Vec<u8>) using provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext: Vec<u8> = encrypt_file(text_vec, key).unwrap();
/// ```
pub fn encrypt_file_aes(
    cleartext: Vec<u8>,
    key: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(key);
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
pub fn encrypt_file_chacha(
    cleartext: Vec<u8>,
    key: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(key);
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
/// let plaintext: Vec<u8> = decrypt_file(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_file_aes(enc: &Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(key);
    let decoded: Cipher = bincode::deserialize(&enc[..]).unwrap();
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string2.as_bytes());
    let plaintext = match aead.decrypt(nonce, ciphertext2.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(_) => "error decrypting".as_bytes().to_owned(),
    };
    //println!("{:?}", std::str::from_utf8(&plaintext).unwrap());
    Ok(plaintext)
}

/// Decrypts ciphertext (Vec<u8>) into cleartext (Vec<u8>) using XChaCha20Poly1305 with provided key from keyfile. Returns result.
/// # Examples
///
/// ```
/// let key: &str = "an example very very secret key.";
/// let plaintext: Vec<u8> = decrypt_file(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_file_chacha(
    enc: &Vec<u8>,
    key: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    key.trim_end();
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(key);
    let decoded: Cipher = bincode::deserialize(&enc[..]).unwrap();
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string2.as_bytes());
    let plaintext = match aead.decrypt(nonce, ciphertext2.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(_) => "error decrypting".as_bytes().to_owned(),
    };
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
    hasher.input(data);

    // read hash digest and consume hasher
    let hash = hasher.result();
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
    hasher.input(data);

    // read hash digest and consume hasher
    let hash = hasher.result();
    Ok(format!("{:?}", hash))
}

/// Count newlines in &str
pub fn count_newlines(s: &str) -> usize {
    s.as_bytes().iter().filter(|&&c| c == b'\n').count()
}

/// Read lines in file
pub fn read_lines<P>(path: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(path)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn get_line_at(path: &PathBuf, line_num: usize) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(path).expect("File not found or cannot be opened");
    let content = BufReader::new(&file);
    let mut lines = content.lines();
    let line = lines
        .nth(line_num)
        .expect("No line found at given position")?;
    Ok(line)
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
        let plaintext = decrypt_file_aes(&ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_encryt_decrypt_chacha() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let text_vec = text.to_vec();
        let ciphertext = encrypt_file_chacha(text_vec, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_file_chacha(&ciphertext, key).unwrap();
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
    fn test_count_lines() {
        let f: String = "some text\nwith\nfour\nlines\n".to_string();
        assert_eq!(count_newlines(&f), 4);
    }

    #[test]
    fn test_all() {
        use std::str::from_utf8;
        let path: PathBuf = PathBuf::from("cargo.toml");
        let key_path = PathBuf::from("key.test");
        create_key(&key_path).unwrap();
        let content_read: Vec<u8> = read_file(&path).unwrap();
        let mut i = 1;
        while i < 1000 {
            let key = read_file(&key_path).unwrap();
            if count_newlines(from_utf8(&key).unwrap()) == 0 {
                let key: &str = from_utf8(&key).unwrap();
                let content = read_file(&path).unwrap();
                let ciphertext: Vec<u8> = encrypt_file_chacha(content, &key).unwrap();
                let new_filename: String =
                    path.clone().into_os_string().into_string().unwrap() + ".crpt";
                let new_filename: PathBuf = PathBuf::from(new_filename);
                //println!("Ciphertext: {:.unwrap()}", &ciphertext);
                save_file(ciphertext, &new_filename).unwrap();
            } else if count_newlines(from_utf8(&key).unwrap()) > 0 {
                use rand::{thread_rng, Rng};
                let mut rng = thread_rng();
                let n: usize = rng.gen_range(0, count_newlines(from_utf8(&key).unwrap()));
                //println!("Key-N° {} used", &n);
                let key: String = if get_line_at(&key_path, n).unwrap().is_empty() {
                    get_line_at(&key_path, 0).unwrap()
                } else {
                    get_line_at(&key_path, n).unwrap()
                };
                let content = read_file(&path).unwrap();
                let ciphertext: Vec<u8> = encrypt_file_chacha(content, &key).unwrap();
                let new_filename: String =
                    path.clone().into_os_string().into_string().unwrap() + ".crpt";
                let new_filename: PathBuf = PathBuf::from(new_filename);
                //println!("Ciphertext: {:.unwrap()}", &ciphertext);
                save_file(ciphertext, &new_filename).unwrap();
            };
            let key = read_file(&keyfile)?;
            if count_newlines(from_utf8(&key)?) == 0 {
                let key: &str = from_utf8(&key)?;
                let filename_two = &filename.clone();
                let filename_decrypted: &str = &filename_two.to_str().unwrap();
                let filename_decrypted: &str =
                    &filename_two.to_str().unwrap().replace("crpt", "plaintext");
                let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
                let ciphertext = read_file(&filename)?;
                //println!("Ciphertext read from file: {:?}", &ciphertext);
                //println!("Decrypted");
                let plaintext: Vec<u8> = decrypt_file_chacha(&ciphertext, &key)?;
                save_file(plaintext, &filename_decrypted_path)?;
                println!(
                    "Successfully decrypted file {:?} to {:?}",
                    filename, filename_decrypted
                );
            } else if count_newlines(from_utf8(&key)?) > 0 {
                //println!("Count: {}", count_newlines(from_utf8(&key)?));
                let key: &str = from_utf8(&key)?;
                let filename_two = &filename.clone();
                let filename_decrypted: &str =
                    &filename_two.to_str().unwrap().replace("crpt", "plaintext");
                let filename_decrypted_path: PathBuf = PathBuf::from(filename_decrypted);
                let ciphertext = read_file(&filename)?;
                //println!("Ciphertext: {:?}", &ciphertext);
                let f = File::open(keyfile)?;
                let f = BufReader::new(f);

                for line in f.lines() {
                    match decrypt_file_chacha(&ciphertext, &line?) {
                        Ok(plaintext) => {
                            if plaintext == "error decrypting".as_bytes() {
                                continue;
                            } else {
                                save_file(plaintext, &filename_decrypted_path)?;
                                println!(
                                    "Successfully decrypted file {:?} to {:?}",
                                    filename, filename_decrypted
                                );
                            }
                            break;
                        }
                        Err(error) => {
                            continue;
                        }
                    }
                }
            };
            i += 1;
        }
    }
}

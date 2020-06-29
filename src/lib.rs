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
//! Can be used as library and a binary target. Install via cargo install enc_file
//!
//! Panics at errors making execution impossible.  
//!
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
// Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability. //
//
// Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for encryption, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.
//
// Generate a new key.file on first run (you can also manually add keys).
//
// Encrypting "example.file" will create a new (encrypted) file "example.file.crpt" in the same directory.
//
// Decrypting "example.file.crpt" will create a new (decrypted) file "example.file" in the same directory.
//
// Both encrypt and decrypt override existing files!
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

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;

use sha2::{Digest, Sha256, Sha512};

use serde::{Deserialize, Serialize};

//Struct to store ciphertext, nonce and ciphertext.len() in file and to read it from file
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Cipher {
    len: usize,
    rand_string: String,
    ciphertext: Vec<u8>,
}

/// Encrypts cleartext (Vec<u8>) with a key (&str) using XChaCha20Poly1305 (24-byte nonce as compared to 12-byte in ChaCha20Poly1305). Returns result (ciphertext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use enc_file::{encrypt_chacha, decrypt_chacha};
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext = encrypt_chacha(text_vec, key).unwrap();
/// assert_ne!(&ciphertext, &text);
/// let plaintext = decrypt_chacha(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn encrypt_chacha(
    cleartext: Vec<u8>,
    key: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);
    //generate random nonce
    let rand_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(24)
        .collect::<String>();
    let nonce = GenericArray::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, cleartext.as_ref())
        .expect("encryption failure!");
    //ciphertext_to_send includes the length of the ciphertext (to confirm upon decryption), the nonce (needed to decrypt) and the actual ciphertext
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    //serialize using bincode. Facilitates storing in file.
    let encoded: Vec<u8> = bincode::serialize(&ciphertext_to_send)?;
    Ok(encoded)
}

/// Decrypts ciphertext (Vec<u8>) with a key (&str) using XChaCha20Poly1305 (24-byte nonce as compared to 12-byte in ChaCha20Poly1305). Returns result (cleartext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use enc_file::{encrypt_chacha, decrypt_chacha};
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext = encrypt_chacha(text_vec, key).unwrap();
/// assert_ne!(&ciphertext, &text);
/// let plaintext = decrypt_chacha(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_chacha(enc: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);

    //deserialize input read from file
    let decoded: Cipher = bincode::deserialize(&enc[..])?;
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    //check if included length of ciphertext == actual length of ciphertext
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string2.as_bytes());
    //decrypt to plaintext
    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext2.as_ref())
        .expect("decryption failure!");
    Ok(plaintext)
}

// Encrypts cleartext (Vec<u8>) with a key (&str) using AES256 GCM SIV. Returns result (ciphertext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use enc_file::{encrypt_aes, decrypt_aes};
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext = encrypt_aes(text_vec, key).unwrap();
/// assert_ne!(&ciphertext, &text);
/// let plaintext = decrypt_aes(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn encrypt_aes(cleartext: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(&key);
    //generate random nonce
    let rand_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(12)
        .collect::<String>();
    let nonce = GenericArray::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, cleartext.as_ref())
        .expect("encryption failure!");
    //ciphertext_to_send includes the length of the ciphertext (to confirm upon decryption), the nonce (needed to decrypt) and the actual ciphertext
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    //serialize using bincode. Facilitates storing in file.
    let encoded: Vec<u8> = bincode::serialize(&ciphertext_to_send)?;
    Ok(encoded)
}

/// Decrypts ciphertext (Vec<u8>) with a key (&str) using AES256 GCM SIV. Returns result (cleartext as Vec<u8>).
///
/// # Examples
///
/// ```
/// use enc_file::{encrypt_aes, decrypt_aes};
/// let text = b"This a test";
/// let key: &str = "an example very very secret key.";
/// let text_vec = text.to_vec();
/// let ciphertext = encrypt_aes(text_vec, key).unwrap();
/// assert_ne!(&ciphertext, &text);
/// let plaintext = decrypt_aes(ciphertext, key).unwrap();
/// assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
/// ```
pub fn decrypt_aes(enc: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(&key);
    //deserialize input read from file
    let decoded: Cipher = bincode::deserialize(&enc[..])?;
    let (ciphertext2, len_ciphertext, rand_string2) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    //check if included length of ciphertext == actual length of ciphertext
    if ciphertext2.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string2.as_bytes());
    //decrypt to plaintext
    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext2.as_ref())
        .expect("decryption failure!");
    Ok(plaintext)
}

/// Reads userinput from stdin and returns it as String. Returns result.
pub fn get_input_string() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    Ok(trimmed)
}

/// Reads file from same folder as Vec<u8>. Returns result.
/// # Examples
///
/// ```
/// use enc_file::read_file;
/// use std::path::PathBuf;
/// let path: PathBuf = PathBuf::from("cargo.toml");
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
/// use enc_file::save_file;
/// use std::path::PathBuf;
/// use std::fs::remove_file;
/// let path: PathBuf = PathBuf::from("test123.testxyz");
/// let ciphertext: Vec<u8> = vec![1 as u8, 2 as u8];
/// save_file(ciphertext, &path).unwrap();
/// remove_file(&path).unwrap(); //remove file created for this text
/// ```
pub fn save_file(data: Vec<u8>, path: &PathBuf) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

/// Get BLAKE3 Hash from data. File needs to be read as Vac<u8> (e.g. use enc_file::read_file()). Returns result.
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use enc_file::{get_blake3_hash, read_file};
/// let filename = PathBuf::from("cargo.toml");
/// let hash1 = get_blake3_hash(read_file(&filename).unwrap()).unwrap();
/// let hash2 = get_blake3_hash(read_file(&filename).unwrap()).unwrap();
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_blake3_hash(data: Vec<u8>) -> Result<blake3::Hash, Box<dyn std::error::Error>> {
    let hash = blake3::hash(&data);
    Ok(hash)
}

/// Get SHA256 Hash from data. File needs to be read as Vac<u8> (e.g. use enc_file::read_file()). Returns result.
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use enc_file::{get_sha256_hash, read_file};
/// let filename = PathBuf::from("cargo.toml");
/// let hash1 = get_sha256_hash(read_file(&filename).unwrap()).unwrap();
/// let hash2 = get_sha256_hash(read_file(&filename).unwrap()).unwrap();
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_sha256_hash(data: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Get SHA512 Hash from data. File needs to be read as Vac<u8> (e.g. use enc_file::read_file()). Returns result.
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use enc_file::{get_sha512_hash, read_file};
/// let filename = PathBuf::from("cargo.toml");
/// let hash1 = get_sha512_hash(read_file(&filename).unwrap()).unwrap();
/// let hash2 = get_sha512_hash(read_file(&filename).unwrap()).unwrap();
/// assert_eq!(hash1, hash2);
/// ```
pub fn get_sha512_hash(data: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    // create a Sha256 object
    let mut hasher = Sha512::new();

    // write input message
    hasher.update(data);

    // read hash digest and consume hasher
    let hash = hasher.finalize();
    Ok(format!("{:?}", hash))
}

/// Allows user to choose desired hashing function. Returns result.
pub fn choose_hashing_function() -> Result<(), Box<dyn std::error::Error>> {
    println!("Please choose type of Hash:\n1 Blake3\n2 SHA256\n3 SHA5212");
    //Get user input
    let answer = get_input_string()?;
    if answer == "1" {
        println!("Calculating Blake3 Hash: please enter file path  ");
        let path = PathBuf::from(get_input_string()?);
        let hash = get_blake3_hash(read_file(&path)?)?;
        println!("Hash Blake3: {:?}", hash);
    } else if answer == "2" {
        println!("Calculating SHA256 Hash: please enter file path  ");
        let path = PathBuf::from(get_input_string()?);
        let hash = get_sha256_hash(read_file(&path)?)?;
        println!("Hash SHA256: {:?}", hash);
    } else if answer == "3" {
        println!("Calculating SHA512 Hash: please enter file path  ");
        let path = PathBuf::from(get_input_string()?);
        let hash = get_sha512_hash(read_file(&path)?)?;
        println!("Hash SHA512: {:?}", hash);
    } else {
        println!("Please choose a corresponding number betwenn 1 and 3")
    }
    Ok(())
}

/// Decrypts file. Taking a keymap "keymap_plaintext" and the choosen encryption "enc" ("chacha" for ChaCha20Poly1305 or "aes" for AES256-GCM-SIV). Returns result.
pub fn decrypt_file(
    keymap_plaintext: HashMap<String, String>,
    enc: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if keymap_plaintext.is_empty() {
        panic!("No keys avaible. Please first add a key.")
    }
    println!("Decrypting file: please enter file path  ");
    let path = PathBuf::from(get_input_string()?);
    let ciphertext = read_file(&path)?;
    let new_filename = PathBuf::from(
        &path
            .to_str()
            .expect("Unable to parse filename!")
            .replace(r#".crpt"#, r#""#),
    );

    println!("Existing keynames");
    for (entry, _) in &keymap_plaintext {
        println!("{}", entry)
    }
    println!("Please provide keyname to decrypt: ");
    let answer = get_input_string()?;
    let key = keymap_plaintext
        .get(&answer)
        .expect("No key with that name");
    let plaintext = if enc == "chacha" {
        decrypt_chacha(ciphertext, key)?
    } else if enc == "aes" {
        decrypt_aes(ciphertext, key)?
    } else {
        panic!()
    };

    save_file(plaintext, &new_filename)?;
    Ok(())
}

/// Encrypts file. Taking a keymap "keymap_plaintext" and the choosen encryption "enc" ("chacha" for ChaCha20Poly1305 or "aes" for AES256-GCM-SIV). Returns result.
pub fn encrypt_file(
    keymap_plaintext: HashMap<String, String>,
    enc: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if keymap_plaintext.is_empty() {
        panic!("No keys avaible. Please first add a key.")
    }
    println!("Encrypting file: please enter file path  ");
    let path = PathBuf::from(get_input_string()?);

    let new_filename = PathBuf::from(
        path.clone()
            .into_os_string()
            .into_string()
            .expect("Unable to parse filename!")
            + r#".crpt"#,
    );

    println!("Existing keynames");
    for (entry, _) in &keymap_plaintext {
        println!("{}", entry)
    }
    let cleartext = read_file(&path)?;
    println!("Please provide keyname to encrypt: ");
    let answer = get_input_string()?;
    let key = keymap_plaintext
        .get(&answer)
        .expect("No key with that name");
    let ciphertext = if enc == "chacha" {
        encrypt_chacha(cleartext, key)?
    } else if enc == "aes" {
        encrypt_aes(cleartext, key)?
    } else {
        panic!()
    };

    save_file(ciphertext, &new_filename)?;
    Ok(())
}

/// Removes choosen key from keymap. Taking a keymap "keymap_plaintext" and user provided password.
pub fn remove_key(
    mut keymap_plaintext: HashMap<String, String>,
    password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if keymap_plaintext.is_empty() {
        panic!("No keys avaible. Please first add a key.")
    }
    println!("Existing keynames");
    for (entry, _) in &keymap_plaintext {
        println!("{}", entry)
    }
    println!("Please provide keyname to delete: ");
    let answer = get_input_string()?;

    match keymap_plaintext.remove(&answer) {
        Some(_) => println!("Key removed"),
        None => println!("No key of this name"),
    }

    //Check if there is a key in keymap
    if keymap_plaintext.is_empty() {
        println!("Warning: No keys available. Please create a new entry")
    }
    let encoded: Vec<u8> = encrypt_hashmap(keymap_plaintext, &password)?;
    fs::write("key.file", encoded)?;
    Ok(())
}

/// Adds key to keymap. Taking a keymap "keymap_plaintext" and user provided password.
pub fn add_key(
    mut keymap_plaintext: HashMap<String, String>,
    password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Please choose name for new key: ");

    //Ask for a name to be associated with the new key
    let key_name = get_input_string()?;

    //Ask if random key should be generate or key will be provided by user
    println!("Create new random key (r) or manually enter a key (m). Key needs to be valid 32-long char-utf8");
    let answer = get_input_string()?;
    let mut key = String::new();
    if answer == "r" {
        let key_rand: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect::<String>();
        key.push_str(&key_rand);
    } else if answer == "m" {
        println!("Please enter key. Must be valid 32-long char-utf8");
        let answer = get_input_string()?;
        // String is always valid utf8, len() still needs to be checked
        if answer.len() == 32 {
            key.push_str(&answer);
        } else {
            println!("Please provide a valid 32-long char-utf8")
        }
    } else {
        //to do
        panic!();
    }
    keymap_plaintext.insert(key_name.trim().to_string(), key.trim().to_string());

    let encoded: Vec<u8> = encrypt_hashmap(keymap_plaintext, &password)?;
    fs::write("key.file", encoded)?;
    Ok(())
}

/// Creates a new keyfile. User can choose to create a random key or manually enter 32-long char-utf8 password in a keyfile. Key has to be valid utf8. Resturns result (password, keyfile and bool (true if new keyfile way created)).
pub fn create_new_keyfile(
) -> Result<(String, HashMap<String, String>, bool), Box<dyn std::error::Error>> {
    println!("No keyfile found. Create a new one? Y/N");
    let answer = get_input_string()?;
    if answer == "y" {
        //Enter a password to encrypt key.file
        println!("Please enter a password (lenth > 8) to encrypt the keyfile: ");

        let mut password = String::new();
        io::stdin()
            .read_line(&mut password)
            .expect("Failed to read line");
        if password.len() < 8 {
            panic!("Password too short!")
        }
        let mut file = File::create("key.file")?;
        println!("Please choose name for new key: ");

        //Ask for a name to be associated with the new key
        let key_name = get_input_string()?;

        //Ask if random key should be generate or key will be provided by user
        println!("Create new random key (r) or manually enter a key (m). Key needs to be valid 32-long char-utf8");
        let answer = get_input_string()?;
        let mut key = String::new();
        if answer == "r" {
            let key_rand: String = OsRng
                .sample_iter(&Alphanumeric)
                .take(32)
                .collect::<String>();
            key.push_str(&key_rand);
        } else if answer == "m" {
            println!("Please enter key. Must be valid 32-long char-utf8");
            let answer = get_input_string()?;
            // String is always valid utf8, len() still needs to be checked
            if answer.len() == 32 {
                key.push_str(&answer);
            } else {
                println!("Please provide a valid 32-long char-utf8")
            }
        } else {
            //to do
            panic!();
        }

        let mut new_key_map = HashMap::new();

        new_key_map.insert(key_name, key);
        let encoded: Vec<u8> = encrypt_hashmap(new_key_map.clone(), &password)?;

        file.write_all(&encoded)?;
        Ok((password, new_key_map, true))
    } else {
        //TO DO
        panic!()
    }
}

/// Read keyfile to keymap. Asks for userpassword. Returns result (password, keymap and bool(false as no new keymap was created))
pub fn read_keyfile() -> Result<(String, HashMap<String, String>, bool), Box<dyn std::error::Error>>
{
    println!("Enter password: ");
    let password = get_input_string()?;
    let hashed_password = blake3::hash(&password.trim().as_bytes());
    //println!("{:?}", hashed_password);
    let mut f = File::open("key.file").expect("Could not open key.file");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let key = GenericArray::clone_from_slice(hashed_password.as_bytes());

    let decoded: Cipher = bincode::deserialize(&buffer[..])?;
    let (ciphertext, len_ciphertext, rand_string) =
        (decoded.ciphertext, decoded.len, decoded.rand_string);
    if ciphertext.len() != len_ciphertext {
        panic!("length of received ciphertext not ok")
    };
    let nonce = GenericArray::from_slice(rand_string.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);

    let plaintext: Vec<u8> = aead
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");
    let keymap_plaintext: HashMap<String, String> = bincode::deserialize(&plaintext[..])?;
    println!("Keys found in key.file:\n{:?}\n", &keymap_plaintext);
    Ok((password, keymap_plaintext, false))
}

/// Encrypt a given hashmap with a given password using ChaCha20Poly1305. Returns result (Vec<u8>)
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
/// use chacha20poly1305::XChaCha20Poly1305;
/// use enc_file::{encrypt_hashmap};
/// use serde::{Deserialize, Serialize};
/// let mut keymap_plaintext: HashMap<String, String> = HashMap::new();
/// keymap_plaintext.insert("Hello".to_string(), "world".to_string());
/// let password: String = "Password".to_string();
/// let encrypted: Vec<u8> = encrypt_hashmap(keymap_plaintext.clone(), &password).unwrap();
/// //test that encrypting 2 times results in different Vec<u8>
/// let encrypted2: Vec<u8> = encrypt_hashmap(keymap_plaintext, &password).unwrap();
/// assert_ne!(encrypted, encrypted2);
/// ```
pub fn encrypt_hashmap(
    keymap_plaintext: HashMap<String, String>,
    password: &String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded: Vec<u8> = bincode::serialize(&keymap_plaintext).expect("Unable to encode keymap!");

    //encrypt Hashmap with keys
    let rand_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(24)
        .collect::<String>();
    let nonce = GenericArray::from_slice(rand_string.as_bytes());
    let hashed_password = blake3::hash(&password.trim().as_bytes());
    let key = GenericArray::clone_from_slice(hashed_password.as_bytes());
    let aead = XChaCha20Poly1305::new(&key);
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, encoded.as_ref())
        .expect("encryption failure!");
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    let encoded: Vec<u8> =
        bincode::serialize(&ciphertext_to_send).expect("Unable to encode keymap!");
    Ok(encoded)
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
        let ciphertext = encrypt_aes(text_vec, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_aes(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_encryt_decrypt_chacha() {
        let text = b"This a test";
        let key: &str = "an example very very secret key.";
        let text_vec = text.to_vec();
        let ciphertext = encrypt_chacha(text_vec, key).unwrap();
        assert_ne!(&ciphertext, &text);
        let plaintext = decrypt_chacha(ciphertext, key).unwrap();
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext));
    }

    #[test]
    fn test_multiple_encrypt_unequal_chacha() {
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
            let ciphertext1 = encrypt_chacha(content.clone(), &key).unwrap();
            let ciphertext2 = encrypt_chacha(content.clone(), &key).unwrap();
            let ciphertext3 = encrypt_chacha(content.clone(), &key).unwrap();
            let ciphertext4 = encrypt_chacha(content.clone(), &key).unwrap();
            let ciphertext5 = encrypt_chacha(content, &key).unwrap();
            assert_ne!(&ciphertext1, &ciphertext2);
            assert_ne!(&ciphertext1, &ciphertext3);
            assert_ne!(&ciphertext1, &ciphertext4);
            assert_ne!(&ciphertext1, &ciphertext5);
            assert_ne!(&ciphertext2, &ciphertext3);
            assert_ne!(&ciphertext2, &ciphertext4);
            assert_ne!(&ciphertext2, &ciphertext5);
            assert_ne!(&ciphertext3, &ciphertext4);
            assert_ne!(&ciphertext3, &ciphertext5);
            assert_ne!(&ciphertext4, &ciphertext5);
            i += 1;
        }
    }

    #[test]
    fn test_multiple_encrypt_unequal_aes() {
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
            let ciphertext1 = encrypt_aes(content.clone(), &key).unwrap();
            let ciphertext2 = encrypt_aes(content.clone(), &key).unwrap();
            let ciphertext3 = encrypt_aes(content.clone(), &key).unwrap();
            let ciphertext4 = encrypt_aes(content.clone(), &key).unwrap();
            let ciphertext5 = encrypt_aes(content, &key).unwrap();
            assert_ne!(&ciphertext1, &ciphertext2);
            assert_ne!(&ciphertext1, &ciphertext3);
            assert_ne!(&ciphertext1, &ciphertext4);
            assert_ne!(&ciphertext1, &ciphertext5);
            assert_ne!(&ciphertext2, &ciphertext3);
            assert_ne!(&ciphertext2, &ciphertext4);
            assert_ne!(&ciphertext2, &ciphertext5);
            assert_ne!(&ciphertext3, &ciphertext4);
            assert_ne!(&ciphertext3, &ciphertext5);
            assert_ne!(&ciphertext4, &ciphertext5);
            i += 1;
        }
    }

    #[test]
    fn test_hash_blake3() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_blake3_hash(read_file(&filename).unwrap()).unwrap();
        let hash2 = get_blake3_hash(read_file(&filename).unwrap()).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sha256() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_sha256_hash(read_file(&filename).unwrap()).unwrap();
        let hash2 = get_sha256_hash(read_file(&filename).unwrap()).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sha512() {
        let filename = PathBuf::from("cargo.toml");
        let hash1 = get_sha512_hash(read_file(&filename).unwrap()).unwrap();
        let hash2 = get_sha512_hash(read_file(&filename).unwrap()).unwrap();
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
            let ciphertext = encrypt_chacha(content.clone(), &key).unwrap();
            assert_ne!(&ciphertext, &content);
            let plaintext = decrypt_chacha(ciphertext, &key).unwrap();
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
            let ciphertext = encrypt_aes(content.clone(), &key).unwrap();
            assert_ne!(&ciphertext, &content);
            let plaintext = decrypt_aes(ciphertext, &key).unwrap();
            assert_eq!(format!("{:?}", content), format!("{:?}", plaintext));

            i += 1;
        }
    }
    #[test]
    fn test_example() {
        let text = b"This a test"; //Text to encrypt
        let key: &str = "an example very very secret key."; //Key will normally be chosen from keymap and provided to the encrypt_chacha() function
        let text_vec = text.to_vec(); //Convert text to Vec<u8>
        let ciphertext = encrypt_chacha(text_vec, key).unwrap(); //encrypt vec<u8>, returns result(Vec<u8>)
                                                                 //let ciphertext = encrypt_chacha(read_file(example.file).unwrap(), key).unwrap(); //read a file as Vec<u8> and then encrypt
        assert_ne!(&ciphertext, &text); //Check that plaintext != ciphertext
        let plaintext = decrypt_chacha(ciphertext, key).unwrap(); //Decrypt ciphertext to plaintext
        assert_eq!(format!("{:?}", text), format!("{:?}", plaintext)); //Check that text == plaintext
    }

    #[test]
    fn test_example_hash() {
        let test = b"Calculating the BLAKE3 Hash of this text";
        let test_vec = test.to_vec(); //Convert text to Vec<u8>
        let hash1 = get_blake3_hash(test_vec.clone()).unwrap();
        let hash2 = get_blake3_hash(test_vec).unwrap();
        assert_eq!(hash1, hash2); //Make sure hash1 == hash2
    }
}

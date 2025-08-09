#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/ArdentEmpiricist/enc_file/main/assets/logo.png"
)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aead::{Aead, KeyInit};
use aes_gcm_siv::Aes256GcmSiv;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose};
use chacha20poly1305::aead::generic_array::{GenericArray, typenum::U19};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill as getrandom;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Default chunk size for streaming (1 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;

// ---------- Public types ----------

/// Supported AEAD algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AeadAlg {
    /// XChaCha20-Poly1305 (24-byte nonces). Supports built-in streaming helpers.
    #[default]
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM-SIV (12-byte nonces). We implement simple counter-based streaming.
    Aes256GcmSiv = 2,
}

/// Supported password KDFs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum KdfAlg {
    #[default]
    Argon2id = 1,
}

impl EncryptOptions {
    /// Enable/disable ASCII armor in a Clippy-friendly way.
    pub fn with_armor(mut self, on: bool) -> Self {
        self.armor = on;
        self
    }
}

/// Tunable KDF parameters (mem_kib in KiB).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub t_cost: u32,
    pub mem_kib: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Interactive defaults; adjust if you need higher resistance.
        Self {
            t_cost: 2,
            mem_kib: 64 * 1024,
            parallelism: 1,
        }
    }
}

/// Options for encryption.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub alg: AeadAlg,
    pub kdf: KdfAlg,
    pub kdf_params: KdfParams,
    /// When `true`, wraps the binary file in an ASCII-armored envelope (Base64).
    pub armor: bool,
    /// When `true`, allow overwriting existing output file paths.
    pub force: bool,
    /// Stream in constant memory using chunked framing (recommended for very large files).
    pub stream: bool,
    /// Chunk size in bytes (only applies when `stream == true`).
    pub chunk_size: usize,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            alg: AeadAlg::default(),
            kdf: KdfAlg::default(),
            kdf_params: KdfParams::default(),
            armor: false,
            force: false,
            stream: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Library error type (no panics for expected failures).
#[derive(Error, Debug)]
pub enum EncFileError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("encryption/decryption failure")]
    Crypto,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported AEAD algorithm id {0}")]
    UnsupportedAead(u8),
    #[error("unsupported KDF algorithm id {0}")]
    UnsupportedKdf(u8),
    #[error("malformed file")]
    Malformed,
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
    #[error("serialization error")]
    Serde(#[from] serde_cbor::Error),
}

// ---------- On-disk header ----------

const MAGIC: &[u8; 8] = b"ENCFILE\0";
const VERSION: u16 = 2;

/// Optional streaming info (present when the file is chunk-framed).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StreamInfo {
    /// Chunk size used by the writer.
    chunk_size: u32,
    /// Nonce prefix for streaming:
    /// - XChaCha20-Poly1305: 19 bytes (used with EncryptorBE32/DecryptorBE32)
    /// - AES-256-GCM-SIV:    8 bytes (we append a 32-bit big-endian counter)
    nonce_prefix: Vec<u8>,
    // For AES-GCM-SIV we increment a 32-bit counter per chunk to build unique nonces.
    // For XChaCha20-Poly1305 the streaming helper manages the counter internally.
}

/// Versioned header (CBOR-encoded). Adding optional fields is forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskHeader {
    magic: [u8; 8],
    version: u16,
    aead_alg: u8,
    kdf_alg: u8,
    kdf_params: KdfParams,
    /// Non-streaming nonce (full length) OR unused when `stream.is_some()`.
    nonce: Vec<u8>,
    /// Per-file KDF salt (16 bytes is typical).
    salt: Vec<u8>,
    /// Total ciphertext length for non-streaming files (used for validation).
    ct_len: u64,
    /// Present when the file is written in streaming mode.
    stream: Option<StreamInfo>,
}

impl DiskHeader {
    fn new_nonstream(
        aead_alg: AeadAlg,
        kdf_alg: KdfAlg,
        kdf_params: KdfParams,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        ct_len: u64,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            aead_alg: aead_alg as u8,
            kdf_alg: kdf_alg as u8,
            kdf_params,
            nonce,
            salt,
            ct_len,
            stream: None,
        }
    }

    fn new_stream(
        aead_alg: AeadAlg,
        kdf_alg: KdfAlg,
        kdf_params: KdfParams,
        salt: Vec<u8>,
        stream: StreamInfo,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            aead_alg: aead_alg as u8,
            kdf_alg: kdf_alg as u8,
            kdf_params,
            nonce: Vec::new(), // unused in streaming mode
            salt,
            ct_len: 0, // not used in streaming mode
            stream: Some(stream),
        }
    }
}

fn write_all_atomic(path: &Path, data: &[u8], mode_600: bool) -> Result<(), EncFileError> {
    use tempfile::NamedTempFile;
    let parent = path
        .parent()
        .ok_or(EncFileError::Invalid("output path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    if mode_600 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
        }
    }
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path).map_err(|e| EncFileError::Io(e.error))?;
    Ok(())
}

// ---------- KDF ----------

fn derive_key_argon2id(
    password: &SecretString,
    params: KdfParams,
    salt: &[u8],
) -> Result<[u8; 32], EncFileError> {
    let argon_params = Params::new(params.mem_kib, params.t_cost, params.parallelism, None)
        .map_err(|_| EncFileError::Invalid("invalid Argon2 params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|_| EncFileError::Crypto)?;
    Ok(out)
}

// ---------- One-shot (non-streaming) helpers ----------

fn aead_encrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

fn aead_decrypt(
    alg: AeadAlg,
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = XNonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let nonce = GenericArray::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| EncFileError::Crypto)
        }
    }
}

fn nonce_len_for(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::XChaCha20Poly1305 => 24,
        AeadAlg::Aes256GcmSiv => 12,
    }
}

// ---------- Public API: in-memory one-shot ----------

/// Encrypt a whole buffer and return the full file bytes (header + ciphertext).
///
/// When `opts.armor == true`, returns ASCII-armored data (Base64) instead of binary.
pub fn encrypt_bytes(
    plaintext: &[u8],
    password: SecretString,
    opts: &EncryptOptions,
) -> Result<Vec<u8>, EncFileError> {
    if opts.stream {
        return Err(EncFileError::Invalid("use streaming APIs for stream mode"));
    }
    let mut salt = vec![0u8; 16];
    getrandom(&mut salt).map_err(|_| EncFileError::Crypto)?;
    let key = derive_key_argon2id(&password, opts.kdf_params, &salt)?;
    let mut nonce = vec![0u8; nonce_len_for(opts.alg)];
    getrandom(&mut nonce).map_err(|_| EncFileError::Crypto)?;

    let ciphertext = aead_encrypt(opts.alg, &key, &nonce, plaintext)?;
    let header = DiskHeader::new_nonstream(
        opts.alg,
        opts.kdf,
        opts.kdf_params,
        salt,
        nonce,
        ciphertext.len() as u64,
    );
    let header_bytes = serde_cbor::to_vec(&header)?;

    let mut out = Vec::with_capacity(4 + header_bytes.len() + ciphertext.len());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);

    let mut key_z = key;
    key_z.zeroize();

    if opts.armor {
        Ok(armor_encode(&out))
    } else {
        Ok(out)
    }
}

/// Decrypt full file bytes into plaintext.
pub fn decrypt_bytes(input: &[u8], password: SecretString) -> Result<Vec<u8>, EncFileError> {
    if looks_armored(input) {
        let bin = dearmor_decode(input)?;
        return decrypt_bytes(&bin, password);
    }

    if input.len() < 4 {
        return Err(EncFileError::Malformed);
    }
    let header_len = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
    if input.len() < 4 + header_len {
        return Err(EncFileError::Malformed);
    }
    let header: DiskHeader = serde_cbor::from_slice(&input[4..4 + header_len])?;

    if &header.magic != MAGIC {
        return Err(EncFileError::Malformed);
    }
    if header.version != VERSION {
        return Err(EncFileError::UnsupportedVersion(header.version));
    }

    let aead_alg = match header.aead_alg {
        1 => AeadAlg::XChaCha20Poly1305,
        2 => AeadAlg::Aes256GcmSiv,
        o => return Err(EncFileError::UnsupportedAead(o)),
    };
    let kdf_alg = match header.kdf_alg {
        1 => KdfAlg::Argon2id,
        o => return Err(EncFileError::UnsupportedKdf(o)),
    };
    let _ = kdf_alg;

    let key = derive_key_argon2id(&password, header.kdf_params, &header.salt)?;
    let body = &input[4 + header_len..];

    if let Some(stream) = &header.stream {
        // Streaming framed ciphertext in memory: parse frames.
        let pt = decrypt_stream_into_vec(aead_alg, &key, stream, body)?;
        let mut key_z = key;
        key_z.zeroize();
        return Ok(pt);
    }

    if body.len() as u64 != header.ct_len {
        return Err(EncFileError::Malformed);
    }
    let pt = aead_decrypt(aead_alg, &key, &header.nonce, body)?;
    let mut key_z = key;
    key_z.zeroize();
    Ok(pt)
}

// ---------- Public API: files (one-shot) ----------

/// Encrypt a file to disk. If `output` is `None`, appends ".enc".
/// Use `opts.stream = true` to enable streaming mode (see `encrypt_file_streaming`).
pub fn encrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    opts: EncryptOptions,
) -> Result<PathBuf, EncFileError> {
    if opts.stream {
        return encrypt_file_streaming(input, output, password, opts);
    }
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    let out_bytes = encrypt_bytes(&data, password, &opts)?;
    let out_path = default_out_path(input, output, "enc");
    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }
    write_all_atomic(&out_path, &out_bytes, false)?;
    Ok(out_path)
}

/// Decrypt a file from disk. If `output` is `None`, strips ".enc" or uses ".dec".
pub fn decrypt_file(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
) -> Result<PathBuf, EncFileError> {
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    let pt = decrypt_bytes(&data, password)?;
    let out_path = default_out_path_for_decrypt(input, output);
    if out_path.exists() {
        return Err(EncFileError::Invalid(
            "output exists; use --force (via CLI) to overwrite",
        ));
    }
    write_all_atomic(&out_path, &pt, false)?;
    Ok(out_path)
}

fn default_out_path(input: &Path, output: Option<&Path>, ext: &str) -> PathBuf {
    output.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let mut p = input.to_path_buf();
        if let Some(e) = input.extension().and_then(|s| s.to_str()) {
            p.set_extension(format!("{e}.{ext}"));
        } else {
            p.set_extension(ext);
        }
        p
    })
}

fn default_out_path_for_decrypt(input: &Path, output: Option<&Path>) -> PathBuf {
    output.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let s = input.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(".enc") {
            PathBuf::from(stripped)
        } else {
            let mut p = input.to_path_buf();
            p.set_extension("dec");
            p
        }
    })
}

// ---------- Optional key map (encrypted file holding named keys) ----------

/// An encrypted key map: name -> raw 32-byte key (opaque).
pub type KeyMap = HashMap<String, Vec<u8>>;

/// Load a key map using a password.
pub fn load_keymap(path: &Path, password: SecretString) -> Result<KeyMap, EncFileError> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let pt = decrypt_bytes(&data, password)?;
    let map: KeyMap = serde_cbor::from_slice(&pt)?;
    Ok(map)
}

/// Save a key map using a password (0600 perms on Unix).
pub fn save_keymap(
    path: &Path,
    password: SecretString,
    map: &KeyMap,
    opts: &EncryptOptions,
) -> Result<(), EncFileError> {
    let pt = serde_cbor::to_vec(map)?;
    let bytes = if opts.stream {
        return Err(EncFileError::Invalid("keymap: streaming not supported"));
    } else {
        encrypt_bytes(&pt, password, opts)?
    };
    write_all_atomic(path, &bytes, true)?;
    Ok(())
}

// ---------- ASCII armor (Base64) ----------

fn armor_encode(binary: &[u8]) -> Vec<u8> {
    let b64 = general_purpose::STANDARD.encode(binary);
    let mut out = Vec::new();
    out.extend_from_slice(b"-----BEGIN ENCFILE-----\n");
    out.extend_from_slice(b64.as_bytes());
    out.extend_from_slice(b"\n-----END ENCFILE-----\n");
    out
}

fn dearmor_decode(data: &[u8]) -> Result<Vec<u8>, EncFileError> {
    let s = std::str::from_utf8(data).map_err(|_| EncFileError::Malformed)?;
    let s = s.trim();
    let body = s
        .strip_prefix("-----BEGIN ENCFILE-----")
        .and_then(|x| x.strip_suffix("-----END ENCFILE-----"))
        .ok_or(EncFileError::Malformed)?;
    let body = body.trim_matches(&['\r', '\n', ' '][..]).trim();
    general_purpose::STANDARD
        .decode(body)
        .map_err(|_| EncFileError::Malformed)
}

pub fn looks_armored(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ENCFILE-----")
}

// ---------- Streaming encryption/decryption ----------
//
// We support two streaming modes:
// - XChaCha20-Poly1305: use EncryptorBE32/DecryptorBE32 with a 19-byte nonce prefix.
// - AES-256-GCM-SIV: manual per-chunk nonces: 8-byte random prefix + 32-bit BE counter.
// Frame format for both algorithms:
//   [u8 flags][u32 ct_len_be][ct_bytes]
// flags: bit0 set => last chunk.

const FLAG_FINAL: u8 = 1;

/// Encrypt a file in streaming mode (constant memory).
pub fn encrypt_file_streaming(
    input: &Path,
    output: Option<&Path>,
    password: SecretString,
    mut opts: EncryptOptions,
) -> Result<PathBuf, EncFileError> {
    if !opts.stream {
        opts.stream = true;
    }
    let chunk = opts.chunk_size.max(1024);
    let out_path = default_out_path(input, output, "enc");

    if out_path.exists() && !opts.force {
        return Err(EncFileError::Invalid(
            "output exists; use --force to overwrite",
        ));
    }

    // Derive key & build header
    let mut salt = vec![0u8; 16];
    getrandom(&mut salt).map_err(|_| EncFileError::Crypto)?;
    let key = derive_key_argon2id(&password, opts.kdf_params, &salt)?;

    // Prepare stream info
    let stream_info = match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            let mut prefix = vec![0u8; 19];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: chunk as u32,
                nonce_prefix: prefix,
            }
        }
        AeadAlg::Aes256GcmSiv => {
            // 8-byte prefix + 32-bit counter per chunk => unique nonces.
            let mut prefix = vec![0u8; 8];
            getrandom(&mut prefix).map_err(|_| EncFileError::Crypto)?;
            StreamInfo {
                chunk_size: chunk as u32,
                nonce_prefix: prefix,
            }
        }
    };

    let header = DiskHeader::new_stream(
        opts.alg,
        opts.kdf,
        opts.kdf_params,
        salt,
        stream_info.clone(),
    );
    let header_bytes = serde_cbor::to_vec(&header)?;

    // Write header then stream frames
    use tempfile::NamedTempFile;
    let parent = out_path.parent().unwrap();
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    tmp.write_all(&header_bytes)?;

    // Input/output streaming
    let mut infile = File::open(input)?;
    let mut buf = vec![0u8; chunk];
    match opts.alg {
        AeadAlg::XChaCha20Poly1305 => {
            // Build cipher from derived key (accepts &[u8])
            let cipher =
                XChaCha20Poly1305::new_from_slice(&key).map_err(|_| EncFileError::Crypto)?;

            // Convert Vec<u8> nonce prefix (must be 19 bytes) to GenericArray nonce reference
            let prefix_arr: [u8; 19] = stream_info
                .nonce_prefix
                .as_slice()
                .try_into()
                .map_err(|_| EncFileError::Malformed)?;
            let nonce_prefix: &GenericArray<u8, U19> =
                GenericArray::<u8, U19>::from_slice(&prefix_arr);

            // Initialize the streaming encryptor
            let mut enc = EncryptorBE32::from_aead(cipher, nonce_prefix);

            // Write non-final frames with encrypt_next
            loop {
                let n = infile.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                let pt = &buf[..n];
                let ct = enc.encrypt_next(pt).map_err(|_| EncFileError::Crypto)?;
                write_frame(&mut tmp, &ct, false)?;
            }

            // Emit a final empty frame (encrypt_last consumes the encryptor)
            let ct_final = enc
                .encrypt_last(&[] as &[u8])
                .map_err(|_| EncFileError::Crypto)?;
            write_frame(&mut tmp, &ct_final, true)?;
        }

        AeadAlg::Aes256GcmSiv => {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| EncFileError::Crypto)?;
            // Counter will be appended to 8-byte prefix => 12-byte nonce.
            let prefix = &stream_info.nonce_prefix;
            let mut counter: u32 = 0;
            loop {
                let n = infile.read(&mut buf)?;
                let is_final = n == 0 || n < chunk;
                let pt = &buf[..n];
                // nonce = prefix (8 bytes) || counter_be (4 bytes)
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(prefix);
                nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);

                let ct = cipher
                    .encrypt(GenericArray::from_slice(&nonce_bytes), pt)
                    .map_err(|_| EncFileError::Crypto)?;
                write_frame(&mut tmp, &ct, is_final)?;
                if is_final {
                    break;
                }
            }
        }
    }

    tmp.as_file_mut().flush()?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(&out_path)
        .map_err(|e| EncFileError::Io(e.error))?;

    // Zeroize derived key
    let mut key_z = key;
    key_z.zeroize();

    Ok(out_path)
}

/// Helper: write a single framed chunk.
fn write_frame<W: Write>(mut w: W, ct: &[u8], is_final: bool) -> Result<(), EncFileError> {
    let flags = if is_final { FLAG_FINAL } else { 0 };
    w.write_all(&[flags])?;
    w.write_all(&(ct.len() as u32).to_be_bytes())?;
    w.write_all(ct)?;
    Ok(())
}

/// Decrypt framed ciphertext (in-memory) using the given header stream info.
fn decrypt_stream_into_vec(
    alg: AeadAlg,
    key: &[u8; 32],
    stream: &StreamInfo,
    body: &[u8],
) -> Result<Vec<u8>, EncFileError> {
    let mut out = Vec::new();
    let mut idx = 0usize;

    match alg {
        AeadAlg::XChaCha20Poly1305 => {
            // Build cipher from derived key (accepts &[u8])
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;

            // Convert stored nonce prefix (must be 19 bytes) to GenericArray
            let prefix_arr: [u8; 19] = stream
                .nonce_prefix
                .as_slice()
                .try_into()
                .map_err(|_| EncFileError::Malformed)?;
            let nonce_prefix: &GenericArray<u8, U19> =
                GenericArray::<u8, U19>::from_slice(&prefix_arr);

            // Initialize the streaming decryptor
            let mut dec = DecryptorBE32::from_aead(cipher, nonce_prefix);

            // Walk all frames: decrypt_next for non-final frames,
            // remember the final frame ciphertext and decrypt it once at the end.
            let mut idx = 0usize;
            //let mut final_ct: Option<&[u8]> = None;

            loop {
                if idx + 1 + 4 > body.len() {
                    return Err(EncFileError::Malformed);
                }

                let flags = body[idx];
                idx += 1;
                let len = u32::from_be_bytes(body[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                if idx + len > body.len() {
                    return Err(EncFileError::Malformed);
                }

                let ct = &body[idx..idx + len];
                idx += len;

                if (flags & FLAG_FINAL) != 0 {
                    // Final chunk: decrypt_last consumes den Decryptor
                    let pt_final = dec.decrypt_last(ct).map_err(|_| EncFileError::Crypto)?;
                    out.extend_from_slice(&pt_final);
                    break;
                } else {
                    // Non-final chunk: decrypt_next
                    let pt = dec.decrypt_next(ct).map_err(|_| EncFileError::Crypto)?;
                    out.extend_from_slice(&pt);
                }
            }
        }

        AeadAlg::Aes256GcmSiv => {
            let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| EncFileError::Crypto)?;
            let prefix = &stream.nonce_prefix;
            let mut counter: u32 = 0;
            loop {
                if idx + 1 + 4 > body.len() {
                    return Err(EncFileError::Malformed);
                }
                let flags = body[idx];
                idx += 1;
                let len = u32::from_be_bytes(body[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                if idx + len > body.len() {
                    return Err(EncFileError::Malformed);
                }
                let ct = &body[idx..idx + len];
                idx += len;

                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(prefix);
                nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);

                let pt = cipher
                    .decrypt(GenericArray::from_slice(&nonce_bytes), ct)
                    .map_err(|_| EncFileError::Crypto)?;
                out.extend_from_slice(&pt);
                if (flags & FLAG_FINAL) != 0 {
                    break;
                }
            }
        }
    }
    Ok(out)
}

// ---------- Hashing API ----------

use std::io::BufReader;

/// Common hashing algorithms your library supports.
///
/// Default is `Blake3` for performance and modern security properties.
/// Add or remove variants as needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlg {
    /// BLAKE3 (32-byte digest). Default.
    #[default]
    Blake3,
    /// SHA-256 (32-byte digest)
    Sha256,
    /// SHA-512 (64-byte digest)
    Sha512,
    /// SHA3-256 (32-byte digest)
    Sha3_256,
    /// SHA3-512 (64-byte digest)
    Sha3_512,
    /// BLAKE2b (64-byte digest; unkeyed mode here)
    Blake2b,
    /// XXH3 64-bit (16-byte digest; NOT cryptographic — integrity only)
    Xxh3_64,
    /// XXH3 128-bit (16-byte digest; NOT cryptographic — integrity only)
    Xxh3_128,
    /// CRC32 (4-byte checksum; NOT cryptographic — integrity only)
    Crc32,
}

/// Hash a byte slice and return the raw digest bytes.
pub fn hash_bytes(data: &[u8], alg: HashAlg) -> Vec<u8> {
    match alg {
        HashAlg::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(data);
            hasher.finalize().as_bytes().to_vec() // 32
        }
        HashAlg::Sha256 => {
            use sha2::{Digest, Sha256};
            Sha256::digest(data).to_vec() // 32
        }
        HashAlg::Sha512 => {
            use sha2::{Digest, Sha512};
            Sha512::digest(data).to_vec() // 64
        }
        HashAlg::Sha3_256 => {
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest(data).to_vec() // 32
        }
        HashAlg::Sha3_512 => {
            use sha3::{Digest, Sha3_512};
            Sha3_512::digest(data).to_vec() // 64
        }
        HashAlg::Blake2b => {
            use blake2::{Blake2b512, Digest};
            Blake2b512::digest(data).to_vec() // 64
        }
        HashAlg::Xxh3_64 => {
            use xxhash_rust::xxh3::xxh3_64;
            xxh3_64(data).to_be_bytes().to_vec() // 8
        }
        HashAlg::Xxh3_128 => {
            use xxhash_rust::xxh3::xxh3_128;
            xxh3_128(data).to_be_bytes().to_vec() // 16
        }
        HashAlg::Crc32 => {
            use crc::{CRC_32_ISO_HDLC, Crc};
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let mut d = crc.digest();
            d.update(data);
            d.finalize().to_be_bytes().to_vec() // 4
        }
    }
}

/// Hash a file (streaming) and return the raw digest bytes.
///
/// Uses a buffered reader and feeds the hasher in chunks.
/// Returns `EncFileError::Io` (assuming you have that) on I/O failures.
pub fn hash_file(path: &Path, alg: HashAlg) -> Result<Vec<u8>, EncFileError> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buf = vec![0u8; 64 * 1024];

    match alg {
        HashAlg::Blake3 => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().as_bytes().to_vec())
        }
        HashAlg::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha512 => {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha3_256 => {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Sha3_512 => {
            use sha3::{Digest, Sha3_512};
            let mut h = Sha3_512::default();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Blake2b => {
            use blake2::{Blake2b512, Digest};
            let mut h = Blake2b512::default(); // 64-Byte Output
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlg::Xxh3_64 => {
            use xxhash_rust::xxh3::Xxh3;
            let mut h = Xxh3::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.digest().to_be_bytes().to_vec())
        }

        HashAlg::Xxh3_128 => {
            use xxhash_rust::xxh3::Xxh3;
            let mut h = Xxh3::new();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(h.digest128().to_be_bytes().to_vec())
        }
        HashAlg::Crc32 => {
            use crc::{CRC_32_ISO_HDLC, Crc};
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            let mut d = crc.digest();
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                d.update(&buf[..n]);
            }
            Ok(d.finalize().to_be_bytes().to_vec())
        }
    }
}

/// Keyed BLAKE3 hash (32-byte key). Only for BLAKE3 — other algorithms ignore keys or use HMACs.
///
/// # Safety
/// - This is *not* a KDF. It is a keyed hash for authentication (like a MAC).
/// - `key32` **must** be a 32-byte secret key.
pub fn hash_bytes_keyed_blake3(data: &[u8], key32: &[u8; 32]) -> [u8; 32] {
    blake3::keyed_hash(key32, data).into()
}

/// Keyed BLAKE3 file hash (streaming).
pub fn hash_file_keyed_blake3(path: &Path, key32: &[u8; 32]) -> Result<[u8; 32], EncFileError> {
    let mut file = File::open(path)?;
    let mut reader = BufReader::new(&mut file);
    let mut buf = vec![0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new_keyed(key32);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Helper to hex-encode (lower-case) for display or logs.
pub fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------- Tests ----------
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn round_trip_small_default() {
        let pw = SecretString::new("pw".into());
        let ct = encrypt_bytes(b"hi", pw.clone(), &EncryptOptions::default()).unwrap();
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, b"hi");
    }

    #[test]
    fn wrong_password_fails() {
        let ct = encrypt_bytes(
            b"data",
            SecretString::new("pw1".into()),
            &EncryptOptions::default(),
        )
        .unwrap();
        let bad = SecretString::new("pw2".into());
        assert!(matches!(decrypt_bytes(&ct, bad), Err(EncFileError::Crypto)));
    }

    #[test]
    fn armor_works() {
        use secrecy::SecretString;

        let pw = SecretString::new("pw".into());
        let opts = EncryptOptions::default().with_armor(true);

        let ct = encrypt_bytes(b"abc", pw.clone(), &opts).unwrap();
        assert!(super::looks_armored(&ct));
        let pt = decrypt_bytes(&ct, pw).unwrap();
        assert_eq!(pt, b"abc");
    }
}

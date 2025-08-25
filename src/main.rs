#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/ArdentEmpiricist/enc_file/main/assets/logo.png"
)]
//! # enc_file — password-based authenticated encryption for files.
//!
//! `enc_file` is a Rust library for encrypting, decrypting, and hashing files or byte arrays.
//! It supports modern AEAD ciphers (XChaCha20-Poly1305, AES-256-GCM-SIV) with Argon2id key derivation.
//!
//! ## Features
//! - **File and byte array encryption/decryption**
//! - **Streaming encryption** for large files (constant memory usage)
//! - **Multiple AEAD algorithms**: XChaCha20-Poly1305, AES-256-GCM-SIV
//! - **Password-based key derivation** using Argon2id
//! - **Key map management** for named symmetric keys
//! - **Flexible hashing API** with support for BLAKE3, SHA2, SHA3, Blake2b, XXH3, and CRC32
//! - **ASCII armor** for encrypted data (Base64 encoding)
//!
//! ## Example: Encrypt and decrypt a byte array
//! ```no_run
//! use enc_file::{encrypt_bytes, decrypt_bytes, EncryptOptions, AeadAlg};
//! use secrecy::SecretString;
//!
//! let password = SecretString::new("mypassword".into());
//! let opts = EncryptOptions {
//!     alg: AeadAlg::XChaCha20Poly1305,
//!     ..Default::default()
//! };
//!
//! let ciphertext = encrypt_bytes(b"Hello, world!", password.clone(), &opts).unwrap();
//! let plaintext = decrypt_bytes(&ciphertext, password).unwrap();
//! assert_eq!(plaintext, b"Hello, world!");
//! ```
//!
//! ## Example: Hash a file
//! ```no_run
//! use enc_file::{hash_file, HashAlg};
//! use std::path::Path;
//!
//! let digest = hash_file(Path::new("myfile.txt"), HashAlg::Blake3).unwrap();
//! println!("Hash: {}", enc_file::to_hex_lower(&digest));
//! ```
//!
//! See function-level documentation for more details.
//!
//! Safety notes
//! - The crate is not audited or reviewed! Protects data at rest. Does not defend against compromised hosts/side channels.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use enc_file::{
    AeadAlg, DEFAULT_CHUNK_SIZE, EncryptOptions, KdfParams, KeyMap, decrypt_file, encrypt_file,
    encrypt_file_streaming, load_keymap, save_keymap,
};
use getrandom::fill as getrandom;
use hex::decode as hex_decode;
use secrecy::SecretString;

#[derive(Parser, Debug)]
#[command(
    name = "enc-file",
    version,
    about = "Encrypt/decrypt files and compute hashes"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt a file (use --stream for large files)
    Enc(EncArgs),
    /// Decrypt a file
    Dec(DecArgs),
    /// Manage an encrypted key map
    #[command(subcommand)]
    Key(KeyCmd),
    /// Compute a file hash (default: blake3)
    Hash(HashArgs),
}

#[derive(Args, Debug)]
struct EncArgs {
    /// Input file
    #[arg(short = 'i', long = "in")]
    input: std::path::PathBuf,

    /// Output file (encrypted). If omitted, ".enc" is appended.
    #[arg(short = 'o', long = "out")]
    output: Option<std::path::PathBuf>,

    #[arg(short = 'a',long, value_enum, default_value_t = AlgChoice::Xchacha)]
    alg: AlgChoice,

    /// ASCII armor the output (Base64) for copy/paste
    #[arg(long)]
    armor: bool,

    /// Overwrite output if it exists
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Enable streaming mode (constant memory; recommended for very large files)
    #[arg(long)]
    stream: bool,

    /// Chunk size for streaming mode (bytes). Default: 1 MiB.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,

    /// Read password from file instead of interactive prompt
    #[arg(short = 'p', long = "password-file")]
    password_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct DecArgs {
    /// Input file (encrypted)
    #[arg(short = 'i', long = "in")]
    input: std::path::PathBuf,

    /// Output file (plaintext). If omitted, ".enc" is stripped or ".dec" is appended.
    #[arg(short = 'o', long = "out")]
    output: Option<std::path::PathBuf>,

    /// Optional path to a file containing the password (trailing newline will be trimmed).
    #[arg(short = 'p', long = "password-file")]
    password_file: Option<std::path::PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(short = 'f', long = "force")]
    force: bool,
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Initialize an empty key map file
    Init(KeyFileArg),
    /// Add a named key (random or from hex)
    Add(KeyAddArgs),
    /// Remove a named key
    Rm(KeyRmArgs),
}

#[derive(Args, Debug)]
struct KeyFileArg {
    #[arg(long = "file")]
    file: PathBuf,
    #[arg(long = "password-file")]
    password_file: Option<PathBuf>,
    /// ASCII armor the key map file (for copy/paste scenarios)
    #[arg(long)]
    armor: bool,
}

#[derive(Args, Debug)]
struct KeyAddArgs {
    #[arg(long = "file")]
    file: PathBuf,
    #[arg(long = "name")]
    name: String,
    #[arg(long = "random", conflicts_with = "from_hex")]
    random: bool,
    #[arg(long = "from-hex", value_name = "HEX", conflicts_with = "random")]
    from_hex: Option<String>,
    #[arg(long = "password-file")]
    password_file: Option<PathBuf>,
    #[arg(long)]
    armor: bool,
}

#[derive(Args, Debug)]
struct KeyRmArgs {
    #[arg(long = "file")]
    file: PathBuf,
    #[arg(long = "name")]
    name: String,
    #[arg(long = "password-file")]
    password_file: Option<PathBuf>,
    #[arg(long)]
    armor: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AlgChoice {
    Xchacha,
    Aes,
}

impl From<AlgChoice> for AeadAlg {
    fn from(v: AlgChoice) -> Self {
        match v {
            AlgChoice::Xchacha => AeadAlg::XChaCha20Poly1305,
            AlgChoice::Aes => AeadAlg::Aes256GcmSiv,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum HashAlgArg {
    Blake3,
    Sha256,
    Sha512,
    #[value(alias = "sha3256", alias = "sha3_256")]
    Sha3_256,
    #[value(alias = "sha3512", alias = "sha3_512")]
    Sha3_512,
    Blake2b,
    #[value(alias = "xxh364", alias = "xxh3-64")]
    Xxh3_64,
    #[value(alias = "xxh3128", alias = "xxh3-128")]
    Xxh3_128,
    Crc32,
}

impl From<HashAlgArg> for enc_file::HashAlg {
    fn from(a: HashAlgArg) -> Self {
        match a {
            HashAlgArg::Blake3 => enc_file::HashAlg::Blake3,
            HashAlgArg::Sha256 => enc_file::HashAlg::Sha256,
            HashAlgArg::Sha512 => enc_file::HashAlg::Sha512,
            HashAlgArg::Sha3_256 => enc_file::HashAlg::Sha3_256,
            HashAlgArg::Sha3_512 => enc_file::HashAlg::Sha3_512,
            HashAlgArg::Blake2b => enc_file::HashAlg::Blake2b,
            HashAlgArg::Xxh3_64 => enc_file::HashAlg::Xxh3_64,
            HashAlgArg::Xxh3_128 => enc_file::HashAlg::Xxh3_128,
            HashAlgArg::Crc32 => enc_file::HashAlg::Crc32,
        }
    }
}

#[derive(Args, Debug)]
pub struct HashArgs {
    /// File to hash
    pub file: PathBuf,

    /// Algorithm to use (Blake3, Sha256, Sha512, Sha3_256, Sha3_512, Blake2b,Xxh3_64, Xxh3_128, Crc32)
    #[arg(long, value_enum, default_value_t = HashAlgArg::Blake3)]
    pub alg: HashAlgArg,

    /// Output raw bytes instead of hex
    #[arg(long)]
    pub raw: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Enc(a) => cmd_enc(a),
        Command::Dec(a) => cmd_dec(a),
        Command::Key(k) => cmd_key(k),
        Command::Hash(h) => cmd_hash(h),
    }
}

fn read_password(password_file: &Option<PathBuf>, prompt: &str) -> Result<SecretString> {
    if let Some(path) = password_file {
        let mut s = String::new();
        fs::File::open(path)?.read_to_string(&mut s)?;

        // Create SecretString directly from trimmed slice to avoid intermediate copies
        let secret = SecretString::new(
            s.trim_end_matches(&['\r', '\n'][..]).to_owned().into_boxed_str()
        );
        
        // Zero the original string that contained the password
        use zeroize::Zeroize;
        s.zeroize();
        Ok(secret)
    } else {
        let pw = rpassword::prompt_password(prompt)?;
        Ok(SecretString::new(pw.into_boxed_str()))
    }
}

fn cmd_enc(a: EncArgs) -> Result<()> {
    let pw = read_password(&a.password_file, "Password: ")?;
    let opts = EncryptOptions {
        alg: AeadAlg::from(a.alg),
        kdf: enc_file::KdfAlg::Argon2id,
        kdf_params: KdfParams::default(),
        armor: a.armor,
        force: a.force,
        stream: a.stream,
        chunk_size: a.chunk_size,
    };

    let out = if a.stream {
        encrypt_file_streaming(&a.input, a.output.as_deref(), pw, opts)
    } else {
        encrypt_file(&a.input, a.output.as_deref(), pw, opts)
    }
    .with_context(|| "encryption failed")?;

    eprintln!("Wrote {}", out.display());
    Ok(())
}

fn cmd_dec(a: DecArgs) -> Result<()> {
    let pw = read_password(&a.password_file, "Password: ")?;

    // Resolve the output path the library will use.
    let target = if let Some(ref out) = a.output {
        out.clone()
    } else {
        compute_default_dec_out(&a.input)
    };

    // Enforce --force at the CLI layer (the library will still refuse if the file exists).
    if target.exists() {
        if a.force {
            // Best-effort removal. If a racy recreate happens, the library will still error safely.
            let _ = std::fs::remove_file(&target);
        } else {
            // Match the library’s wording so tests stay stable.
            anyhow::bail!("output exists; use --force to overwrite");
        }
    }

    // Call the library; pass `a.output.as_deref()` so the lib can use the explicit out if present.
    let out =
        decrypt_file(&a.input, a.output.as_deref(), pw).with_context(|| "decryption failed")?;

    eprintln!("Wrote {}", out.display());
    Ok(())
}

fn cmd_key(k: KeyCmd) -> Result<()> {
    match k {
        KeyCmd::Init(args) => {
            let pw = read_password(&args.password_file, "Key map password: ")?;
            let map: KeyMap = Default::default();
            let opts = EncryptOptions {
                armor: args.armor,
                ..Default::default()
            };
            save_keymap(&args.file, pw, &map, &opts)?;
            eprintln!("Initialized empty key map at {}", args.file.display());
            Ok(())
        }
        KeyCmd::Add(args) => {
            let pw = read_password(&args.password_file, "Key map password: ")?;
            let mut map = load_keymap(&args.file, pw.clone()).unwrap_or_default();
            if map.contains_key(&args.name) {
                anyhow::bail!("key '{}' already exists", args.name);
            }
            let key = if args.random {
                let mut k = vec![0u8; 32];
                getrandom(&mut k).map_err(|e| anyhow::anyhow!(e))?;
                k
            } else if let Some(hex_str) = args.from_hex {
                let bytes = hex_decode(hex_str).context("invalid hex")?;
                if bytes.len() != 32 {
                    anyhow::bail!("key must be 32 bytes (64 hex chars)");
                }
                bytes
            } else {
                anyhow::bail!("specify --random or --from-hex")
            };
            map.insert(args.name.clone(), key);
            let opts = EncryptOptions {
                armor: args.armor,
                ..Default::default()
            };
            save_keymap(&args.file, pw, &map, &opts)?;
            eprintln!("Added key '{}'", args.name);
            Ok(())
        }
        KeyCmd::Rm(args) => {
            let pw = read_password(&args.password_file, "Key map password: ")?;
            let mut map = load_keymap(&args.file, pw.clone()).context("failed to load key map")?;
            if map.remove(&args.name).is_none() {
                anyhow::bail!("key '{}' not found", args.name);
            }
            let opts = EncryptOptions {
                armor: args.armor,
                ..Default::default()
            };
            save_keymap(&args.file, pw, &map, &opts)?;
            eprintln!("Removed key '{}'", args.name);
            Ok(())
        }
    }
}

fn cmd_hash(args: HashArgs) -> anyhow::Result<()> {
    use std::io::Write;
    let digest = enc_file::hash_file(&args.file, args.alg.into())?;
    if args.raw {
        std::io::stdout().write_all(&digest)?;
    } else {
        println!("{}", enc_file::to_hex_lower(&digest));
    }
    Ok(())
}

/// Compute default plaintext output path used by the library when `--out` is omitted:
/// - If input ends with ".enc" (as a suffix), strip it.
/// - Otherwise, append ".dec".
fn compute_default_dec_out(input: &Path) -> PathBuf {
    let s = input.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(".enc") {
        PathBuf::from(stripped)
    } else {
        let mut p = input.to_path_buf();
        p.set_extension("dec");
        p
    }
}

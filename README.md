[![Rust](https://github.com/LazyEmpiricist/enc_file/workflows/Rust/badge.svg?branch=main)](https://github.com/LazyEmpiricist/enc_file)
[![Crates.io](https://img.shields.io/crates/v/enc_file)](https://crates.io/crates/enc_file)
[![Documentation](https://docs.rs/enc_file/badge.svg)](https://docs.rs/enc_file/)
[![Crates.io](https://img.shields.io/crates/l/enc_file)](https://github.com/LazyEmpiricist/enc_file/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/d/enc_file?color=darkblue)](https://crates.io/crates/enc_file)
[![Deploy](https://github.com/ArdentEmpiricist/enc_file/actions/workflows/deploy.yml/badge.svg)](https://github.com/ArdentEmpiricist/enc_file/actions/workflows/deploy.yml)

# enc_file

<p align="center">
  <img src="https://github.com/ArdentEmpiricist/enc_file/blob/main/assets/logo.png" alt="enc_file Logo" width="200"/>
</p>

Password-based, authenticated file encryption with a small versioned header and Argon2id KDF. Ships as both a **library** and a **CLI**.

> **Security note**: This project is **neither** audited **nor** reviewed. It protects data at rest but cannot defend a compromised host or advanced side channels. Use at your own risk. For important or sensitive information, use Veracrypt (or similar) instead.

## Features

- **Argon2id** password KDF (per-file salt + stored parameters).
- AEAD: **XChaCha20-Poly1305** (default) or **AES-256-GCM-SIV**.
- Compact **binary header** (magic, version, alg, KDF kind/params, salt, nonce, length).
- Optional **ASCII armor** for transport.
- **Streaming mode** for large files (constant memory; configurable `chunk_size`).
- Zeroize-sensitive buffers and use `secrecy` wrappers.
- Compute a file hash and print it as hex.
- Usable as **library** and **CLI**.

---

## Install

You can install **enc-file** in several ways:

### From crates.io (requires Rust toolchain)
```bash
cargo install enc-file
```

### From GitHub Releases (prebuilt binaries)
1. Visit the [Releases page](https://github.com/ArdentEmpiricist/enc_file/releases).
2. Download the binary for your platform.
3. Place it in a directory in your `PATH`.

### From source
```bash
# from source
cargo build --release
# binary
target/release/enc-file --help
```

Add to a project as a library:

```toml
# Cargo.toml
[dependencies]
enc_file = "0.5.0"
```

Available optional features (check Cargo.toml): `aes` for AES-256-GCM-SIV.

---

## CLI Usage

```
enc-file <SUBCOMMAND>

Subcommands:
  enc     Encrypt a file (use --stream for large files)
  dec     Decrypt a file
  key     Manage an encrypted key map
  hash    Compute a file hash and print it as hex
```

### Encrypt

```bash
# Simple: prompts for password (if your CLI is set up that way) or read from file if supported
enc-file enc --in secret.pdf --out secret.enc --alg xchacha
```

Options of interest:
- `--alg` / `-a` AEAD algorithm: `xchacha` (default), `aes`
- `--stream` stream mode for large inputs
- `--chunk-size <bytes>` chunk size in streaming mode (default from library)
- `--armor` ASCII-armor output
- `--force` overwrite output if it exists
- `--password-file <PATH>` read password from a file (if your CLI wiring includes it)

### Decrypt

```bash
enc-file dec --in secret.enc --out secret.pdf
```

### Hash

```bash
# Default blake3
enc-file hash README.md
# Specific algorithm (see below)
enc-file hash README.md --alg sha256
```

### Key map (optional)

If you use the library’s key map helpers, the CLI can provide small helpers to init/save/load (if wired). Check `enc-file key --help` for available subcommands.

---

## Library Usage

### Encrypt / Decrypt bytes

```rust
use enc_file::{encrypt_bytes, decrypt_bytes, EncryptOptions, AeadAlg};
use secrecy::SecretString;

let pw = SecretString::new("correct horse battery staple".into());
let opts = EncryptOptions {
    alg: AeadAlg::XChaCha20Poly1305,
    ..Default::default()
};

let ct = encrypt_bytes(b"hello", pw.clone(), &opts)?;
let pt = decrypt_bytes(&ct, pw)?;
assert_eq!(pt, b"hello");
# Ok::<(), enc_file::EncFileError>(())
```

### Encrypt / Decrypt files

```rust
use enc_file::{encrypt_file, decrypt_file, EncryptOptions, AeadAlg};
use secrecy::SecretString;
use std::path::Path;

let pw = SecretString::new("pw".into());
let opts = EncryptOptions {
    alg: AeadAlg::XChaCha20Poly1305, // or AeadAlg::Aes256GcmSiv (with "aes" feature)
    stream: false,  // set true for large files
    armor: false,
    ..Default::default()
};

let out = encrypt_file(Path::new("in.bin"), Some(Path::new("out.enc")), pw.clone(), opts)?;
let back = decrypt_file(&out, Some(Path::new("back.bin")), pw)?;
assert!(back.exists());
# Ok::<(), enc_file::EncFileError>(())
```

### Streaming encryption

```rust
use enc_file::{encrypt_file_streaming, EncryptOptions, AeadAlg};
use secrecy::SecretString;
use std::path::Path;

let pw = SecretString::new("pw".into());
let opts = EncryptOptions {
    alg: AeadAlg::XChaCha20Poly1305,
    stream: true,
    chunk_size: 1024 * 1024, // 1 MiB chunks (example)
    ..Default::default()
};
let out = encrypt_file_streaming(Path::new("big.dat"), None, pw, opts)?;
# Ok::<(), enc_file::EncFileError>(())
```

### Hash helpers

### Supported Hash Algorithms

Both the CLI and library support multiple hashing algorithms for files and byte slices:
| Algorithm            | CLI `--alg` value(s)                                      | Output length |
|----------------------|-----------------------------------------------------------|---------------|
| **BLAKE3**           | `blake3`                                                  | 32 bytes      |
| **BLAKE2b-512**      | `blake2b`                                                 | 64 bytes      |
| **SHA-256**          | `sha256`                                                  | 32 bytes      |
| **SHA-512**          | `sha512`                                                  | 64 bytes      |
| **SHA3-256**         | `sha3-256`, `sha3256`, `sha3_256`                         | 32 bytes      |
| **SHA3-512**         | `sha3-512`, `sha3512`, `sha3_512`                         | 64 bytes      |
| **XXH3-64**          | `xxh3-64`, `xxh364`                                       | 8 bytes       |
| **XXH3-128**         | `xxh3-128`, `xxh3128`                                     | 16 bytes      |
| **CRC32**            | `crc32`                                                   | 4 bytes       |


**CLI Example**:
```bash
# Compute SHA3-512 hash of a file
enc-file hash --file data.bin --alg sha3-512

# Use XXH3-64 (fast, non-cryptographic)
enc-file hash --file data.bin --alg xxh3-64
```

**Library Example**:
```rust
use enc_file::{hash_file, to_hex_lower, HashAlg};
let digest = hash_file(std::path::Path::new("data.bin"), HashAlg::Sha3_512)?;
println!("{}", to_hex_lower(&digest));
# Ok::<(), enc_file::EncFileError>(())
```


```rust
use enc_file::{hash_bytes, hash_file, to_hex_lower, HashAlg};

let digest = hash_bytes(b"abc", HashAlg::Sha256);
assert_eq!(
    to_hex_lower(&digest),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);

let file_digest = hash_file(std::path::Path::new("README.md"), HashAlg::Blake3)?;
println!("{}", to_hex_lower(&file_digest));
# Ok::<(), enc_file::EncFileError>(())
```

### Keyed BLAKE3 (MAC-style)

```rust
use enc_file::hash_bytes_keyed_blake3;
let key = [0u8; 32];
let tag = hash_bytes_keyed_blake3(b"message", &key);
assert_eq!(tag.len(), 32);
# Ok::<(), ()>(())
```

### Key map helpers

```rust
use enc_file::{KeyMap, load_keymap, save_keymap};
use secrecy::SecretString;
use std::path::Path;

let mut km = KeyMap::new();
km.insert("service".into(), "supersecret".into());

let pw = SecretString::new("pw".into());
let path = Path::new("keymap.enc");
save_keymap(&km, path, pw.clone())?;

let loaded = load_keymap(path, pw)?;
assert_eq!(loaded, km);
# Ok::<(), enc_file::EncFileError>(())
```

---

## Error handling

All fallible APIs return `Result<_, EncFileError>`. Common cases:
- `EncFileError::Io` I/O failures
- `EncFileError::Crypto` AEAD failures (bad password, tamper)
- `EncFileError::Format` header parsing/validation issues

---

## Tips

- Use *streaming* for large files to keep memory predictable.
- Consider `--armor` when moving ciphertexts through systems that mangle binaries.
- For CLI automation, prefer `--password-file` over interactive prompts.

---

## License

Licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt)
- [MIT license](LICENSE)

at your option.

Any contribution intentionally submitted for inclusion in this work shall be
dual licensed as above, without any additional terms or conditions.

---

**Note on names**

The library crate is named `enc_file` (snake_case), which is the name you use when importing it in Rust code:

```rust
use enc_file::{hash_file, HashAlg};
```

The compiled CLI binary is named `enc-file` (kebab-case), which is the name you use when invoking it from the shell:

```bash
enc-file hash --file test.txt
```

This naming separation is intentional and follows common conventions.

---

## Feedback & Issues

Feedback, bug reports, and pull requests are highly appreciated! Open an [Issue](https://github.com/ArdentEmpiricist/enc_file/issues) or [start a discussion](https://github.com/ArdentEmpiricist/enc_file/discussions).


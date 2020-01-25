# Enc-File
Simple tool to encrypt and decrypt files. Written in Rust. Warning: Don't use for anything important, use VeraCrypt or similar instead.

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Uses AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography and bincode (https://docs.rs/bincode) for encoding.

Either generate a random keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile.

"cargo run encrypt example.file key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.

"cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.

"cargo run hash example-file" will output BLAKE3 hash of this file.

Both encrypt and decrypt override existing files!

Issues and feedback are highly appreciated. 

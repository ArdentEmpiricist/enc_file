# Enc-File
Simple tool to encrypt / decrypt / hash files. Written in Rust. Warning: Don't use for anything important, use VeraCrypt or similar instead.

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.

Encrypted files are (and have to be) stored as .crpt.

Either generate a keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile. Key has to be valid utf8.

"cargo run encrypt example.file key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.

"cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.

"cargo run hash example-file" will output BLAKE3 hash of the file.

"cargo run hash_sha256 example-file" will output SHA2 256 hash of the file.

"cargo run hash_sha512 example-file" will output SHA2 512 hash of the file.

Both encrypt and decrypt override existing files!

Issues and feedback are highly appreciated. 

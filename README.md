# Enc-File
Encrypt / decrypt files or calculate the HASH from the command line. Written in Rust without unsafe code. Warning: Don't use for anything important, use VeraCrypt or similar instead.

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Breaking change in Version 0.3: Using a keymap to work with several keys conveniently. You can import your old keys, using "Add key" and choose "manually". Interface changes, making it easier to use.

Breaking change in Version 0.2: Using XChaCha20Poly1305 as default encryption/decryption. AES is still available using encrypt_aes or decrypt_aes to maintain backwards compability.

Uses XChaCha20Poly1305 (https://docs.rs/chacha20poly1305) or AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) for encoding and BLAKE3 (https://docs.rs/blake3) or SHA256 / SHA512 (https://docs.rs/sha2) for hashing.

Encrypted files are (and have to be) stored as .crpt.

Both encrypt and decrypt override existing files!

Issues and feedback are highly appreciated. 

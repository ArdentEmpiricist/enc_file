# Enc-File
Simple tool to encrypt / decrypt / hash files. Written in Rust. Warning: Don't use for anything important, use VeraCrypt or similar instead.

This crate hasn't been audited or reviewed in any sense. I created it to easily encrypt und decrypt non-important files which won't cause harm if known by third parties.

To install: clone the repository and build from source or use cargo install enc_file.

Uses AES-GCM-SIV (https://docs.rs/aes-gcm-siv) for cryptography, bincode (https://docs.rs/bincode) and serde (https://docs.serde.rs/serde/) for encoding, BLAKE3 (https://docs.rs/blake3) and SHA2(https://docs.rs/sha2).

Either generate a random keyfile via "cargo run create-key key.file" or use own 32-long char-utf8 password in a keyfile.

"cargo run encrypt example.file key.file" will create a new (encrypted) file "example.file.crypt" in the same directory.

"cargo run decrypt example.file.crypt key.file" will create a new (decrypted) file "example.file" in the same directory.

"cargo run hash example-file" will output BLAKE3 hash of the file.

"cargo run hash_sha256 example-file" will output SHA2 256 hash of the file.

"cargo run hash_sha512 example-file" will output SHA2 512 hash of the file.

Both encrypt and decrypt override existing files!

Issues and feedback are highly appreciated. 

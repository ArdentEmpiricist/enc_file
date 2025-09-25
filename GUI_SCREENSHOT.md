# EncFile GUI Interface

## Main Interface - Encrypt Mode

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ 🔐 EncFile - Secure File Encryption                                           │
└────────────────────────────────────────────────────────────────────────────────┘

Mode: [🔒 Encrypt] [🔓 Decrypt] [🔍 Hash]

───────────────────────────────────────────────────────────────────────────────────

Input file:  [Select file to encrypt              ]
📁 /home/user/documents/secret-document.pdf

Output file: [Choose output location               ]
💾 /home/user/documents/secret-document.pdf.enc

Password:    [●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●]
Confirm:     [●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●]
Strength:    Strong

Algorithm:   [XChaCha20-Poly1305 (Recommended) ▼]

▶ Advanced   Click to show advanced options

                    [🔒 Encrypt File]
```

## Advanced Options Expanded

```
▼ Advanced   

┌──────────────────────────────────────────────────────────────────────────────┐
│ Advanced Options                                                             │
│                                                                              │
│ ☐ Use streaming mode (for large files)                                      │
│ ☐ ASCII armor output (Base64 encoding)                                      │
│ ☐ Force overwrite existing files                                            │
│                                                                              │
│ ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│ Key Derivation (KDF) Parameters                                             │
│                                                                              │
│ Memory cost (KiB):     [────────●────────] 65536                            │
│ Time cost (iterations): [──●─────────────] 3                                │
│ Parallelism:           [───●─────────────] 4                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Progress Display During Operation

```
───────────────────────────────────────────────────────────────────────────────────

🔄 Encrypting file...

████████████████████████████████████████████████████████████████████████████ 85%

Encrypting with streaming mode...
```

## Results Display

```
───────────────────────────────────────────────────────────────────────────────────

✅ Operation completed successfully!

┌──────────────────────────────────────────────────────────────────────────────┐
│ File encrypted successfully!                                                │
│ Output: /home/user/documents/secret-document.pdf.enc                        │
│                                                                              │
│ Algorithm: XChaCha20-Poly1305                                                │
│ File size: 2.5 MB → 2.5 MB (encrypted)                                      │
│ Processing time: 1.2 seconds                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

[📋 Copy to Clipboard] [🗑 Clear]
```

## Hash Mode Interface

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ 🔐 EncFile - Secure File Encryption                                           │
└────────────────────────────────────────────────────────────────────────────────┘

Mode: [🔒 Encrypt] [🔓 Decrypt] [🔍 Hash]

───────────────────────────────────────────────────────────────────────────────────

Input file:  [Select file to hash                 ]
📁 /home/user/documents/important-file.pdf

Hash algorithm: [BLAKE3 (Recommended) ▼]

                    [🔍 Calculate Hash]

───────────────────────────────────────────────────────────────────────────────────

✅ Hash calculated successfully!

┌──────────────────────────────────────────────────────────────────────────────┐
│ Algorithm: BLAKE3                                                            │
│ File: /home/user/documents/important-file.pdf                               │
│ Hash: 8f7a2b1c9d4e5f6a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3    │
└──────────────────────────────────────────────────────────────────────────────┘

[📋 Copy to Clipboard] [🗑 Clear]
```
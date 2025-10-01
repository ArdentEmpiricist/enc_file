# EncFile GUI Design

The GUI provides a modern, cross-platform interface for the enc_file encryption tool.

## Key Features

### Main Interface
- **Tab-like Mode Selection**: Encrypt | Decrypt | Hash modes
- **Clean Layout**: Organized sections with proper spacing
- **File Selection**: Native file picker buttons with drag-and-drop support
- **Password Fields**: Secure input with strength indicator
- **Progress Display**: Real-time progress bars and status messages

### Advanced Options Panel
- **Collapsible Section**: "▶ Advanced" button to expand/collapse
- **Algorithm Selection**: Dropdown for XChaCha20-Poly1305 vs AES-256-GCM-SIV
- **Streaming Options**: Toggle for large file handling
- **Chunk Size Controls**: Input field with auto-sizing option
- **Output Options**: ASCII armor checkbox
- **KDF Parameters**: Sliders for memory, time cost, and parallelism

### UI Layout (Text Representation)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 🔐 EncFile - Secure File Encryption                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ Mode: [🔒 Encrypt] [🔓 Decrypt] [🔍 Hash]                              │
│                                                                         │
│ ─────────────────────────────────────────────────────────────────────── │
│                                                                         │
│ Input file:  [Select file to encrypt]                                  │
│ 📁 /home/user/secret.pdf                                               │
│                                                                         │
│ Output file: [Choose output location]                                  │
│ 💾 /home/user/secret.pdf.enc                                           │
│                                                                         │
│ Password:    [●●●●●●●●●●●●●●●●]                                        │
│ Confirm:     [●●●●●●●●●●●●●●●●]                                        │
│ Strength:    Strong                                                     │
│                                                                         │
│ Algorithm:   [XChaCha20-Poly1305 (Recommended) ▼]                      │
│                                                                         │
│ ▶ Advanced                                                              │
│                                                                         │
│ [🔒 Encrypt File]                                                       │
│                                                                         │
│ ─────────────────────────────────────────────────────────────────────── │
│                                                                         │
│ 🔄 Encrypting file...                                                   │
│ ████████████████████████████████████████████████ 75%                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Advanced Options Expanded

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ▼ Advanced                                                              │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Advanced Options                                                    │ │
│ │                                                                     │ │
│ │ ☐ Use streaming mode (for large files)                             │ │
│ │ ☐ ASCII armor output (Base64 encoding)                             │ │
│ │ ☐ Force overwrite existing files                                   │ │
│ │                                                                     │ │
│ │ ───────────────────────────────────────────────────────────────── │ │
│ │                                                                     │ │
│ │ Key Derivation (KDF) Parameters                                    │ │
│ │                                                                     │ │
│ │ Memory cost (KiB):  [────────●───] 65536                           │ │
│ │ Time cost (iterations): [──●─────] 3                               │ │
│ │ Parallelism:        [──●─────] 2                                   │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Results Display

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ─────────────────────────────────────────────────────────────────────── │
│                                                                         │
│ ✅ Operation completed successfully!                                    │
│                                                                         │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ File encrypted successfully!                                        │ │
│ │ Output: /home/user/secret.pdf.enc                                   │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│ [📋 Copy to Clipboard] [🗑 Clear]                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Technical Implementation

### Architecture
- **egui**: Modern immediate mode GUI framework
- **eframe**: Application framework with cross-platform support
- **rfd**: Native file dialogs
- **tokio**: Async runtime for background operations
- **mpsc channels**: Progress updates and result communication

### Cross-Platform Support
- **Windows**: Native Windows executable
- **macOS**: Native macOS app bundle
- **Linux**: Works with X11 and Wayland

### Performance
- **Non-blocking UI**: Operations run in background threads
- **Progress Updates**: Real-time feedback during encryption/decryption
- **Memory Efficient**: Streaming support for large files
- **Responsive**: UI remains interactive during operations

## User Experience

### Workflows

**Basic Encryption:**
1. Select "Encrypt" mode
2. Choose input file (auto-suggests output path)
3. Enter password (with strength indicator)
4. Click "Encrypt File"
5. View progress and results

**Advanced Usage:**
1. Expand "Advanced" options
2. Configure streaming, algorithms, KDF parameters
3. Enable ASCII armor if needed
4. Proceed with operation

**Hash Calculation:**
1. Select "Hash" mode
2. Choose file and algorithm
3. Click "Calculate Hash"
4. Copy hash result to clipboard

### Error Handling
- **Clear Error Messages**: User-friendly error descriptions
- **Input Validation**: Real-time feedback on password strength, file paths
- **Graceful Failures**: Proper cleanup and user notification
- **Recovery Options**: Clear buttons to reset state

### Accessibility
- **Keyboard Navigation**: Full keyboard support
- **Clear Visual Hierarchy**: Proper contrast and spacing
- **Progress Indication**: Both visual and text-based progress
- **Screen Reader Support**: Proper labeling and structure
#!/bin/bash

# Build script for EncFile GUI

set -e

echo "Building EncFile GUI..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo is not installed. Please install Rust first."
    echo "Visit: https://rustup.rs/"
    exit 1
fi

# Build the GUI version
echo "Building GUI version..."
cargo build --release --features gui

echo "Build completed successfully!"
echo "GUI executable: ./target/release/enc-file-gui"
echo "CLI executable: ./target/release/enc-file"

# Make executable (for Unix systems)
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    chmod +x ./target/release/enc-file-gui
    chmod +x ./target/release/enc-file
fi

echo ""
echo "To run the GUI: ./target/release/enc-file-gui"
echo "To run the CLI: ./target/release/enc-file --help"
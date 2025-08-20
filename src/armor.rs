//! ASCII armor encoding and decoding for encrypted data.

use crate::types::EncFileError;
use base64::{engine::general_purpose, Engine};

/// Encode binary data with ASCII armor (Base64 with PEM-style headers).
///
/// The output format is:
/// ```text
/// -----BEGIN ENCFILE-----
/// <base64-encoded-data>
/// -----END ENCFILE-----
/// ```
pub fn armor_encode(binary: &[u8]) -> Vec<u8> {
    let b64 = general_purpose::STANDARD.encode(binary);
    let mut out = Vec::new();
    out.extend_from_slice(b"-----BEGIN ENCFILE-----\n");
    out.extend_from_slice(b64.as_bytes());
    out.extend_from_slice(b"\n-----END ENCFILE-----\n");
    out
}

/// Decode ASCII-armored data back to binary.
///
/// Expects the standard ENCFILE armor format with BEGIN/END headers.
/// Whitespace around the Base64 content is trimmed.
pub fn dearmor_decode(data: &[u8]) -> Result<Vec<u8>, EncFileError> {
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

/// Check if data appears to be ASCII-armored.
///
/// This is a fast check that only looks at the beginning of the data
/// to see if it starts with the expected armor header.
pub fn looks_armored(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ENCFILE-----")
}
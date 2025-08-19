//! ASCII armor encoding and decoding for encrypted data.

use base64::{Engine, engine::general_purpose};
use crate::types::EncFileError;

pub fn armor_encode(binary: &[u8]) -> Vec<u8> {
    let b64 = general_purpose::STANDARD.encode(binary);
    let mut out = Vec::new();
    out.extend_from_slice(b"-----BEGIN ENCFILE-----\n");
    out.extend_from_slice(b64.as_bytes());
    out.extend_from_slice(b"\n-----END ENCFILE-----\n");
    out
}

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

pub fn looks_armored(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN ENCFILE-----")
}
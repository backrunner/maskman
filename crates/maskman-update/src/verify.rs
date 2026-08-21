use std::io::Read;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::blocking::{Client, Response};
use sha2::{Digest, Sha256};

use crate::UpdateError;

pub(crate) fn download_limited(
    http: &Client,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, UpdateError> {
    if !url.starts_with("https://") {
        return Err(UpdateError::Http("release assets must use HTTPS".into()));
    }
    let mut response = http
        .get(url)
        .send()
        .map_err(|error| UpdateError::Http(error.to_string()))?
        .error_for_status()
        .map_err(|error| UpdateError::Http(error.to_string()))?;
    if response.url().scheme() != "https" {
        return Err(UpdateError::Http("release asset redirect must remain on HTTPS".into()));
    }
    reject_oversized(&response, limit)?;
    read_limited(&mut response, limit)
}

fn reject_oversized(response: &Response, limit: usize) -> Result<(), UpdateError> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        Err(UpdateError::DownloadTooLarge(limit))
    } else {
        Ok(())
    }
}

fn read_limited(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, UpdateError> {
    let mut bytes = Vec::new();
    reader.take(limit.saturating_add(1) as u64).read_to_end(&mut bytes).map_err(UpdateError::Io)?;
    if bytes.len() > limit {
        return Err(UpdateError::DownloadTooLarge(limit));
    }
    Ok(bytes)
}

pub(crate) fn verify_checksum(archive: &[u8], checksum: &[u8]) -> Result<(), UpdateError> {
    let text = String::from_utf8_lossy(checksum);
    let expected = text
        .split_whitespace()
        .find(|value| {
            value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
        })
        .ok_or(UpdateError::DigestMismatch)?;
    let digest = Sha256::digest(archive);
    let actual = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(UpdateError::DigestMismatch);
    }
    Ok(())
}

pub(crate) fn verify_signature(
    archive: &[u8],
    encoded: &[u8],
    key: &VerifyingKey,
) -> Result<(), UpdateError> {
    let signature = if encoded.len() == 64 {
        Signature::from_slice(encoded).map_err(|_| UpdateError::SignatureEncoding)?
    } else {
        let text = String::from_utf8_lossy(encoded).trim().to_owned();
        if text.len() == 128 && text.chars().all(|character| character.is_ascii_hexdigit()) {
            let mut bytes = [0u8; 64];
            for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
                bytes[index] = (hex_digit(chunk[0]).ok_or(UpdateError::SignatureEncoding)? << 4)
                    | hex_digit(chunk[1]).ok_or(UpdateError::SignatureEncoding)?;
            }
            Signature::from_bytes(&bytes)
        } else {
            let bytes = BASE64.decode(text).map_err(|_| UpdateError::SignatureEncoding)?;
            Signature::from_slice(&bytes).map_err(|_| UpdateError::SignatureEncoding)?
        }
    };
    key.verify(archive, &signature).map_err(|_| UpdateError::SignatureInvalid)
}

pub(crate) fn decode_public_key(value: &str) -> Result<VerifyingKey, UpdateError> {
    let bytes = decode_hex(value).ok_or(UpdateError::SignatureEncoding)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| UpdateError::SignatureEncoding)
}

fn decode_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
    }
    Some(bytes)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{read_limited, verify_checksum, verify_signature};
    use crate::UpdateError;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use sha2::Digest;

    #[test]
    fn checksum_and_signature_reject_tampering() {
        let archive = b"signed archive";
        let signing = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let key = VerifyingKey::from(&signing);
        let signature = signing.sign(archive).to_bytes();
        let digest = sha2::Sha256::digest(archive);
        let checksum = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        assert!(verify_checksum(archive, checksum.as_bytes()).is_ok());
        assert!(verify_signature(archive, &signature, &key).is_ok());
        assert!(verify_checksum(b"tampered", checksum.as_bytes()).is_err());
    }

    #[test]
    fn response_reader_stops_at_the_hard_limit() {
        let mut input = std::io::Cursor::new(vec![0u8; 1_024]);
        let result = read_limited(&mut input, 64);
        assert!(matches!(result, Err(UpdateError::DownloadTooLarge(64))));
        assert!(input.position() <= 65);
    }
}

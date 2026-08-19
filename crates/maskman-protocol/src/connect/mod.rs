mod ip;
mod udp;

pub use ip::{parse_ip_path, IpProtocolScope, IpScope, IpTarget};
pub use udp::{parse_udp_path, TargetHost, UdpTarget};

use percent_encoding::percent_decode_str;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathError {
    #[error("path does not match the configured {kind} endpoint")]
    PrefixMismatch { kind: &'static str },
    #[error("{field} path contains a query or fragment")]
    QueryOrFragment { field: &'static str },
    #[error("{field} path has the wrong number of segments")]
    SegmentCount { field: &'static str },
    #[error("{field} segment is empty")]
    EmptySegment { field: &'static str },
    #[error("{field} contains a malformed percent escape")]
    InvalidPercentEncoding { field: &'static str },
    #[error("{field} is not valid UTF-8")]
    InvalidUtf8 { field: &'static str },
    #[error("{field} contains a forbidden character")]
    ForbiddenCharacter { field: &'static str },
    #[error("{field} wildcard must be transmitted as %2A")]
    BareWildcard { field: &'static str },
    #[error("{field} requires percent-encoded {character}")]
    LiteralMustBeEncoded { field: &'static str, character: char },
    #[error("{field} is invalid: {value}")]
    InvalidValue { field: &'static str, value: String },
    #[error("{field} is outside the range {minimum}..={maximum}")]
    OutOfRange { field: &'static str, minimum: u64, maximum: u64 },
}

pub(crate) fn endpoint_segments<'a>(
    path: &'a str,
    base_path: &str,
    kind: &'static str,
) -> Result<Vec<&'a str>, PathError> {
    if path.contains(['?', '#']) {
        return Err(PathError::QueryOrFragment { field: kind });
    }
    let base = base_path.trim_end_matches('/');
    let prefix = if base.is_empty() { format!("/{kind}/") } else { format!("{base}/{kind}/") };
    let Some(rest) = path.strip_prefix(&prefix) else {
        return Err(PathError::PrefixMismatch { kind });
    };
    let Some(rest) = rest.strip_suffix('/') else {
        return Err(PathError::SegmentCount { field: kind });
    };
    let segments: Vec<_> = rest.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(PathError::EmptySegment { field: kind });
    }
    Ok(segments)
}

pub(crate) fn require_segment_count<'a>(
    segments: Vec<&'a str>,
    expected: usize,
    field: &'static str,
) -> Result<Vec<&'a str>, PathError> {
    if segments.len() != expected {
        return Err(PathError::SegmentCount { field });
    }
    Ok(segments)
}

pub(crate) fn decode_segment(raw: &str, field: &'static str) -> Result<String, PathError> {
    if !raw.is_ascii() {
        return Err(PathError::ForbiddenCharacter { field });
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(PathError::InvalidPercentEncoding { field });
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| PathError::InvalidUtf8 { field })?
        .into_owned();
    if decoded.chars().any(|character| character.is_control() || character == ' ') {
        return Err(PathError::ForbiddenCharacter { field });
    }
    Ok(decoded)
}

pub(crate) fn reject_literal(
    raw: &str,
    character: char,
    field: &'static str,
) -> Result<(), PathError> {
    if raw.contains(character) {
        return Err(PathError::LiteralMustBeEncoded { field, character });
    }
    Ok(())
}

pub(crate) fn decode_wildcard(
    raw: &str,
    decoded: String,
    field: &'static str,
) -> Result<String, PathError> {
    if decoded == "*" && !raw.eq_ignore_ascii_case("%2a") {
        return Err(PathError::BareWildcard { field });
    }
    Ok(decoded)
}

pub(crate) fn parse_decimal(
    value: &str,
    field: &'static str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, PathError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PathError::InvalidValue { field, value: value.to_owned() });
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| PathError::InvalidValue { field, value: value.to_owned() })?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(PathError::OutOfRange { field, minimum, maximum });
    }
    Ok(parsed)
}

pub(crate) fn validate_name(value: &str, field: &'static str) -> Result<(), PathError> {
    if value.is_empty() || value.len() > 253 || value.contains(['/', '?', '#', '[', ']', ':', '%'])
    {
        return Err(PathError::InvalidValue { field, value: value.to_owned() });
    }
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte))
    {
        return Err(PathError::InvalidValue { field, value: value.to_owned() });
    }
    Ok(())
}

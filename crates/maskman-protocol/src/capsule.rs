use thiserror::Error;

use crate::varint::{self, VarIntError};

pub const DATAGRAM_CAPSULE: u64 = 0x00;
pub const ADDRESS_ASSIGN_CAPSULE: u64 = 0x01;
pub const ADDRESS_REQUEST_CAPSULE: u64 = 0x02;
pub const ROUTE_ADVERTISEMENT_CAPSULE: u64 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub capsule_type: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    #[error("capsule varint is invalid: {0}")]
    VarInt(#[from] VarIntError),
    #[error("capsule length {length} exceeds configured limit {limit}")]
    TooLarge { length: u64, limit: usize },
    #[error("incomplete capsule buffer exceeds configured limit {limit}")]
    BufferTooLarge { length: usize, limit: usize },
}

#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn push(
        &mut self,
        input: &[u8],
        max_value_bytes: usize,
    ) -> Result<Vec<Capsule>, CapsuleError> {
        let mut capsules = Vec::new();
        let buffer_limit = max_value_bytes.saturating_add(16);
        let mut offset = 0;
        while offset < input.len() || !self.buffer.is_empty() {
            if self.buffer.is_empty() {
                match parse_one(&input[offset..], max_value_bytes)? {
                    ParseOutcome::Complete(capsule, consumed) => {
                        capsules.push(capsule);
                        offset += consumed;
                    }
                    ParseOutcome::Incomplete(required) => {
                        let limit = required.unwrap_or(buffer_limit).min(buffer_limit);
                        let remaining = &input[offset..];
                        let take = remaining.len().min(limit);
                        self.buffer.extend_from_slice(&remaining[..take]);
                        if take < remaining.len() && self.buffer.len() >= limit {
                            return Err(CapsuleError::BufferTooLarge {
                                length: self.buffer.len(),
                                limit,
                            });
                        }
                        break;
                    }
                }
                continue;
            }

            let required = incomplete_size(&self.buffer, max_value_bytes)?;
            let limit = required.unwrap_or(buffer_limit).min(buffer_limit);
            if self.buffer.len() > limit {
                return Err(CapsuleError::BufferTooLarge { length: self.buffer.len(), limit });
            }
            let remaining = &input[offset..];
            let take = remaining.len().min(limit - self.buffer.len());
            self.buffer.extend_from_slice(&remaining[..take]);
            offset += take;
            match parse_one(&self.buffer, max_value_bytes)? {
                ParseOutcome::Complete(capsule, _) => {
                    capsules.push(capsule);
                    self.buffer.clear();
                }
                ParseOutcome::Incomplete(_) => {
                    if self.buffer.len() == limit {
                        return Err(CapsuleError::BufferTooLarge {
                            length: self.buffer.len(),
                            limit,
                        });
                    }
                    if offset == input.len() {
                        break;
                    }
                    if take == 0 {
                        return Err(CapsuleError::BufferTooLarge {
                            length: self.buffer.len(),
                            limit,
                        });
                    }
                }
            }
        }
        Ok(capsules)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

enum ParseOutcome {
    Complete(Capsule, usize),
    Incomplete(Option<usize>),
}

fn parse_one(input: &[u8], max_value_bytes: usize) -> Result<ParseOutcome, CapsuleError> {
    let Some((capsule_type, type_len)) = try_decode(input)? else {
        return Ok(ParseOutcome::Incomplete(None));
    };
    let Some((length, length_len)) = try_decode(&input[type_len..])? else {
        return Ok(ParseOutcome::Incomplete(None));
    };
    if length > max_value_bytes as u64 {
        return Err(CapsuleError::TooLarge { length, limit: max_value_bytes });
    }
    let value_start = type_len + length_len;
    let end = value_start
        .checked_add(length as usize)
        .ok_or(CapsuleError::TooLarge { length, limit: max_value_bytes })?;
    if input.len() < end {
        return Ok(ParseOutcome::Incomplete(Some(end)));
    }
    Ok(ParseOutcome::Complete(
        Capsule { capsule_type, value: input[value_start..end].to_vec() },
        end,
    ))
}

fn incomplete_size(input: &[u8], max_value_bytes: usize) -> Result<Option<usize>, CapsuleError> {
    let Some((_, type_len)) = try_decode(input)? else {
        return Ok(None);
    };
    let Some((length, length_len)) = try_decode(&input[type_len..])? else {
        return Ok(None);
    };
    if length > max_value_bytes as u64 {
        return Err(CapsuleError::TooLarge { length, limit: max_value_bytes });
    }
    Ok(Some(type_len + length_len + length as usize))
}

pub fn encode(capsule: &Capsule, output: &mut Vec<u8>) -> Result<(), VarIntError> {
    let mut varint = [0; 8];
    let type_len = varint::encode(capsule.capsule_type, &mut varint)?;
    output.extend_from_slice(&varint[..type_len]);
    let value_len = varint::encode(capsule.value.len() as u64, &mut varint)?;
    output.extend_from_slice(&varint[..value_len]);
    output.extend_from_slice(&capsule.value);
    Ok(())
}

fn try_decode(input: &[u8]) -> Result<Option<(u64, usize)>, VarIntError> {
    match varint::decode(input) {
        Ok(value) => Ok(Some(value)),
        Err(VarIntError::Truncated) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, Capsule, Decoder, DATAGRAM_CAPSULE};

    #[test]
    fn decoder_handles_split_capsule() {
        let capsule = Capsule { capsule_type: DATAGRAM_CAPSULE, value: b"payload".to_vec() };
        let mut encoded = Vec::new();
        match encode(&capsule, &mut encoded) {
            Ok(()) => {}
            Err(error) => panic!("valid capsule: {error}"),
        }
        let mut decoder = Decoder::default();
        let partial = match decoder.push(&encoded[..2], 1024) {
            Ok(value) => value,
            Err(error) => panic!("partial capsule: {error}"),
        };
        assert!(partial.is_empty());
        let complete = match decoder.push(&encoded[2..], 1024) {
            Ok(value) => value,
            Err(error) => panic!("complete capsule: {error}"),
        };
        assert_eq!(complete, vec![capsule]);
    }

    #[test]
    fn decoder_rejects_large_value_before_allocating() {
        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.push(&[DATAGRAM_CAPSULE as u8, 33], 32),
            Err(super::CapsuleError::TooLarge { .. })
        ));
    }

    #[test]
    fn decoder_accepts_many_capsules_in_one_input() {
        let mut encoded = Vec::new();
        for value in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
            encode(
                &Capsule { capsule_type: DATAGRAM_CAPSULE, value: value.to_vec() },
                &mut encoded,
            )
            .unwrap_or_else(|error| panic!("encode test capsule: {error}"));
        }
        let mut decoder = Decoder::default();
        let decoded = decoder
            .push(&encoded, 1)
            .unwrap_or_else(|error| panic!("decode test capsules: {error}"));
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn decoder_bounds_incomplete_input() {
        let mut decoder = Decoder::default();
        let result = decoder.push(&[0xc0], 4);
        assert!(result.is_ok());
        assert_eq!(decoder.buffered_len(), 1);
        assert!(decoder.push(&[], 4).is_ok());
    }
}

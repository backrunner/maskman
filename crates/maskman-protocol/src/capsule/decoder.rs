use thiserror::Error;

use crate::varint::{self, VarIntError};

use super::{
    Capsule, ADDRESS_ASSIGN_CAPSULE, ADDRESS_REQUEST_CAPSULE, DATAGRAM_CAPSULE,
    ROUTE_ADVERTISEMENT_CAPSULE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleLimits {
    pub max_datagram_bytes: usize,
    pub max_address_bytes: usize,
    pub max_route_bytes: usize,
}

impl CapsuleLimits {
    pub const fn uniform(max_value_bytes: usize) -> Self {
        Self {
            max_datagram_bytes: max_value_bytes,
            max_address_bytes: max_value_bytes,
            max_route_bytes: max_value_bytes,
        }
    }

    fn value_limit(self, capsule_type: u64) -> Option<usize> {
        match capsule_type {
            DATAGRAM_CAPSULE => Some(self.max_datagram_bytes),
            ADDRESS_ASSIGN_CAPSULE | ADDRESS_REQUEST_CAPSULE => Some(self.max_address_bytes),
            ROUTE_ADVERTISEMENT_CAPSULE => Some(self.max_route_bytes),
            _ => None,
        }
    }
}

impl Default for CapsuleLimits {
    fn default() -> Self {
        Self {
            max_datagram_bytes: 65_535,
            max_address_bytes: 64 * 1024,
            max_route_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    UnknownType,
    Oversized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedCapsule {
    pub capsule_type: u64,
    pub length: u64,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeEvent {
    Capsule(Capsule),
    Skipped(SkippedCapsule),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecoderError {
    #[error("invalid capsule header: {0}")]
    VarInt(#[from] VarIntError),
    #[error("capsule stream ended with a truncated capsule")]
    Truncated,
}

#[derive(Debug)]
pub struct Decoder {
    limits: CapsuleLimits,
    state: State,
}

#[derive(Debug)]
enum State {
    Header(HeaderState),
    Value(ValueState),
}

#[derive(Debug, Default)]
struct HeaderState {
    bytes: [u8; 16],
    length: usize,
}

#[derive(Debug)]
struct ValueState {
    capsule_type: u64,
    length: u64,
    remaining: u64,
    disposition: ValueDisposition,
}

#[derive(Debug)]
enum ValueDisposition {
    Buffer(Vec<u8>),
    Skip(SkipReason),
}

impl Decoder {
    pub fn new(limits: CapsuleLimits) -> Self {
        Self { limits, state: State::Header(HeaderState::default()) }
    }

    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<DecodeEvent>, DecoderError> {
        let mut events = Vec::new();
        while !input.is_empty() {
            match &mut self.state {
                State::Header(header) => {
                    header.bytes[header.length] = input[0];
                    header.length += 1;
                    input = &input[1..];
                    if let Some((capsule_type, value_length)) = header.complete()? {
                        self.state = State::Value(ValueState::new(
                            capsule_type,
                            value_length,
                            self.limits.value_limit(capsule_type),
                        ));
                        self.finish_empty_value(&mut events);
                    }
                }
                State::Value(value) => {
                    let consumed = usize::try_from(value.remaining.min(input.len() as u64))
                        .unwrap_or(input.len());
                    if let ValueDisposition::Buffer(buffer) = &mut value.disposition {
                        buffer.extend_from_slice(&input[..consumed]);
                    }
                    value.remaining -= consumed as u64;
                    input = &input[consumed..];
                    if value.remaining == 0 {
                        if let Some(event) = self.finish_value() {
                            events.push(event);
                        }
                    }
                }
            }
        }
        Ok(events)
    }

    pub fn finish(&self) -> Result<(), DecoderError> {
        match &self.state {
            State::Header(header) if header.length == 0 => Ok(()),
            State::Header(_) | State::Value(_) => Err(DecoderError::Truncated),
        }
    }

    pub fn buffered_len(&self) -> usize {
        match &self.state {
            State::Header(header) => header.length,
            State::Value(value) => match &value.disposition {
                ValueDisposition::Buffer(buffer) => buffer.len(),
                ValueDisposition::Skip(_) => 0,
            },
        }
    }

    fn finish_empty_value(&mut self, events: &mut Vec<DecodeEvent>) {
        if matches!(&self.state, State::Value(value) if value.remaining == 0) {
            if let Some(event) = self.finish_value() {
                events.push(event);
            }
        }
    }

    fn finish_value(&mut self) -> Option<DecodeEvent> {
        let previous = std::mem::replace(&mut self.state, State::Header(HeaderState::default()));
        let State::Value(value) = previous else {
            return None;
        };
        Some(match value.disposition {
            ValueDisposition::Buffer(bytes) => {
                DecodeEvent::Capsule(Capsule { capsule_type: value.capsule_type, value: bytes })
            }
            ValueDisposition::Skip(reason) => DecodeEvent::Skipped(SkippedCapsule {
                capsule_type: value.capsule_type,
                length: value.length,
                reason,
            }),
        })
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(CapsuleLimits::default())
    }
}

impl HeaderState {
    fn complete(&self) -> Result<Option<(u64, u64)>, VarIntError> {
        let Some((capsule_type, type_length)) = try_decode(&self.bytes[..self.length])? else {
            return Ok(None);
        };
        let Some((value_length, _)) = try_decode(&self.bytes[type_length..self.length])? else {
            return Ok(None);
        };
        Ok(Some((capsule_type, value_length)))
    }
}

impl ValueState {
    fn new(capsule_type: u64, length: u64, limit: Option<usize>) -> Self {
        let disposition = match limit {
            None => ValueDisposition::Skip(SkipReason::UnknownType),
            Some(limit) if length > limit as u64 => ValueDisposition::Skip(SkipReason::Oversized),
            Some(_) => ValueDisposition::Buffer(Vec::with_capacity(length as usize)),
        };
        Self { capsule_type, length, remaining: length, disposition }
    }
}

fn try_decode(input: &[u8]) -> Result<Option<(u64, usize)>, VarIntError> {
    match varint::decode(input) {
        Ok(value) => Ok(Some(value)),
        Err(VarIntError::Truncated) => Ok(None),
        Err(error) => Err(error),
    }
}

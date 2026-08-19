use thiserror::Error;

use crate::varint::{self, VarIntError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramPayload<'a> {
    pub context_id: u64,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DatagramError {
    #[error("HTTP Datagram context ID is invalid: {0}")]
    VarInt(#[from] VarIntError),
    #[error("UDP context-0 payload length {length} exceeds 65527 bytes")]
    UdpPayloadTooLarge { length: usize },
}

pub fn decode_datagram(input: &[u8]) -> Result<DatagramPayload<'_>, DatagramError> {
    let (context_id, consumed) = varint::decode(input)?;
    Ok(DatagramPayload { context_id, payload: &input[consumed..] })
}

pub fn encode_datagram(
    context_id: u64,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), DatagramError> {
    let mut encoded = [0; 8];
    let length = varint::encode(context_id, &mut encoded)?;
    output.extend_from_slice(&encoded[..length]);
    output.extend_from_slice(payload);
    Ok(())
}

pub fn validate_udp_payload(datagram: &DatagramPayload<'_>) -> Result<(), DatagramError> {
    if datagram.context_id == 0 && datagram.payload.len() > 65_527 {
        return Err(DatagramError::UdpPayloadTooLarge { length: datagram.payload.len() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_datagram, encode_datagram, validate_udp_payload};

    #[test]
    fn round_trips_context_and_payload() {
        let mut encoded = Vec::new();
        encode_datagram(4, b"payload", &mut encoded)
            .unwrap_or_else(|error| panic!("encode datagram: {error}"));
        let decoded = decode_datagram(&encoded).unwrap_or_else(|error| panic!("decode: {error}"));
        assert_eq!(decoded.context_id, 4);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn rejects_truncated_context() {
        assert!(decode_datagram(&[0x40]).is_err());
    }

    #[test]
    fn enforces_udp_context_zero_limit() {
        let payload = vec![0; 65_528];
        let decoded = decode_datagram(&[0]).unwrap_or_else(|error| panic!("decode: {error}"));
        assert!(validate_udp_payload(&decoded).is_ok());
        let mut wire = vec![0];
        wire.extend_from_slice(&payload);
        let decoded = decode_datagram(&wire).unwrap_or_else(|error| panic!("decode: {error}"));
        assert!(validate_udp_payload(&decoded).is_err());
    }
}

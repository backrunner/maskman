use bytes::Bytes;
use thiserror::Error;

const MAX_QUARTER_STREAM_ID: u64 = (1 << 60) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDatagram {
    pub stream_id: u64,
    pub payload: Bytes,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DatagramError {
    #[error("HTTP datagram Quarter Stream ID is invalid")]
    InvalidStreamId,
    #[error("HTTP datagram Quarter Stream ID is truncated")]
    Truncated,
}

pub fn decode(input: Bytes) -> Result<HttpDatagram, DatagramError> {
    let (quarter_stream_id, consumed) =
        maskman_protocol::varint::decode(&input).map_err(|error| match error {
            maskman_protocol::varint::VarIntError::Truncated => DatagramError::Truncated,
            maskman_protocol::varint::VarIntError::Overflow => DatagramError::InvalidStreamId,
        })?;
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(DatagramError::InvalidStreamId);
    }
    let stream_id = quarter_stream_id.checked_mul(4).ok_or(DatagramError::InvalidStreamId)?;
    Ok(HttpDatagram { stream_id, payload: input.slice(consumed..) })
}

pub fn encode(stream_id: u64, payload: Bytes) -> Result<Bytes, DatagramError> {
    if !stream_id.is_multiple_of(4) {
        return Err(DatagramError::InvalidStreamId);
    }
    let quarter_stream_id = stream_id / 4;
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(DatagramError::InvalidStreamId);
    }
    let mut prefix = [0; 8];
    let length = maskman_protocol::varint::encode(quarter_stream_id, &mut prefix)
        .map_err(|_| DatagramError::InvalidStreamId)?;
    let mut output = Vec::with_capacity(length + payload.len());
    output.extend_from_slice(&prefix[..length]);
    output.extend_from_slice(&payload);
    Ok(Bytes::from(output))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{decode, encode, DatagramError};

    #[test]
    fn round_trips_multiple_request_streams() {
        for stream_id in [0, 4, 8, 252, (1 << 62) - 4] {
            let encoded = encode(stream_id, Bytes::from_static(b"payload"))
                .unwrap_or_else(|error| panic!("encode HTTP datagram: {error}"));
            let decoded =
                decode(encoded).unwrap_or_else(|error| panic!("decode HTTP datagram: {error}"));
            assert_eq!(decoded.stream_id, stream_id);
            assert_eq!(decoded.payload, Bytes::from_static(b"payload"));
        }
    }

    #[test]
    fn rejects_non_request_stream_id() {
        assert_eq!(encode(3, Bytes::new()), Err(DatagramError::InvalidStreamId));
    }

    #[test]
    fn rejects_truncated_quarter_stream_id() {
        assert_eq!(decode(Bytes::from_static(&[0x40])), Err(DatagramError::Truncated));
    }
}

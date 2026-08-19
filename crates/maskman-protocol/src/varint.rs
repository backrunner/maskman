use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VarIntError {
    #[error("buffer is truncated")]
    Truncated,
    #[error("value is greater than the QUIC 62-bit maximum")]
    Overflow,
}

pub const MAX_VARINT: u64 = (1 << 62) - 1;

pub fn decode(input: &[u8]) -> Result<(u64, usize), VarIntError> {
    let first = *input.first().ok_or(VarIntError::Truncated)?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return Err(VarIntError::Truncated);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    if value > MAX_VARINT {
        return Err(VarIntError::Overflow);
    }
    Ok((value, length))
}

pub fn encode(value: u64, output: &mut [u8]) -> Result<usize, VarIntError> {
    if value > MAX_VARINT {
        return Err(VarIntError::Overflow);
    }
    let length = if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    };
    if output.len() < length {
        return Err(VarIntError::Truncated);
    }
    let prefix = match length {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    let bytes = value.to_be_bytes();
    output[..length].copy_from_slice(&bytes[8 - length..]);
    output[0] |= prefix;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trips_boundary_values() {
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
            let mut encoded = [0; 8];
            let length = match encode(value, &mut encoded) {
                Ok(length) => length,
                Err(error) => panic!("test value is valid: {error}"),
            };
            assert_eq!(decode(&encoded[..length]), Ok((value, length)));
        }
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(decode(&[0x40]), Err(super::VarIntError::Truncated));
    }
}

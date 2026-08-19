use crate::varint::{self, VarIntError};

use super::Capsule;

pub fn encode(capsule: &Capsule, output: &mut Vec<u8>) -> Result<(), VarIntError> {
    let mut encoded = [0; 8];
    let type_length = varint::encode(capsule.capsule_type, &mut encoded)?;
    output.extend_from_slice(&encoded[..type_length]);
    let value_length = varint::encode(capsule.value.len() as u64, &mut encoded)?;
    output.extend_from_slice(&encoded[..value_length]);
    output.extend_from_slice(&capsule.value);
    Ok(())
}

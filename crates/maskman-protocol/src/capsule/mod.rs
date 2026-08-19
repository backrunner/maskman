mod address;
mod datagram;
mod decoder;
mod encoder;
mod route;

pub use address::{
    decode_address_assign, decode_address_request, encode_address_assign, encode_address_request,
    AddressAssignments, AddressError, AssignedAddress, RequestedAddress,
};
pub use datagram::{
    decode_datagram, encode_datagram, validate_udp_payload, DatagramError, DatagramPayload,
};
pub use decoder::{CapsuleLimits, DecodeEvent, Decoder, DecoderError, SkipReason, SkippedCapsule};
pub use encoder::encode;
pub use route::{
    decode_route_advertisement, encode_route_advertisement, AddressRange, RouteAdvertisement,
    RouteError,
};

pub const DATAGRAM_CAPSULE: u64 = 0x00;
pub const ADDRESS_ASSIGN_CAPSULE: u64 = 0x01;
pub const ADDRESS_REQUEST_CAPSULE: u64 = 0x02;
pub const ROUTE_ADVERTISEMENT_CAPSULE: u64 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub capsule_type: u64,
    pub value: Vec<u8>,
}

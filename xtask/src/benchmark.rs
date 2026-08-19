use std::time::Instant;

use maskman_protocol::{
    capsule::{decode_datagram, encode, encode_datagram, Capsule, CapsuleLimits, Decoder},
    packet::PacketView,
};

pub fn run(iterations: u64) -> Result<(), String> {
    if iterations == 0 {
        return Err("benchmark iterations must be greater than zero".into());
    }
    let mut datagram = Vec::with_capacity(513);
    encode_datagram(0, &[0x42; 512], &mut datagram).map_err(|error| error.to_string())?;
    let capsule = Capsule { capsule_type: 0, value: datagram.clone() };
    let mut encoded = Vec::with_capacity(520);
    let packet = ipv4_fixture();
    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        encoded.clear();
        encode(&capsule, &mut encoded).map_err(|error| error.to_string())?;
        let mut decoder = Decoder::new(CapsuleLimits::uniform(2048));
        checksum =
            checksum.wrapping_add(decoder.push(&encoded).map_err(|error| error.to_string())?.len());
        checksum = checksum.wrapping_add(
            decode_datagram(&datagram).map_err(|error| error.to_string())?.payload.len(),
        );
        checksum = checksum.wrapping_add(
            PacketView::parse(&packet).map_err(|error| error.to_string())?.total_len(),
        );
    }
    let elapsed = started.elapsed();
    let nanos = elapsed.as_nanos().max(1);
    let ops_per_second = (u128::from(iterations) * 3 * 1_000_000_000) / nanos;
    println!(
        "benchmark codec_packet iterations={} elapsed_ms={} ops_per_second={} checksum={}",
        iterations,
        elapsed.as_millis(),
        ops_per_second,
        checksum
    );
    Ok(())
}

fn ipv4_fixture() -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 16];
    packet[0] = 0x45;
    let packet_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[100, 96, 0, 2]);
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks_exact(2) {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([word[0], word[1]])));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !sum as u16
}

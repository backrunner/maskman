use std::{
    fs,
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};

use maskman_protocol::{
    capsule::{decode_datagram, encode, encode_datagram, Capsule, CapsuleLimits, Decoder},
    packet::PacketView,
};

const MAX_ITERATIONS: u64 = 100_000_000;
const MAX_PAYLOADS: usize = 8;
const MAX_LATENCY_SAMPLES: u64 = 1_000_000;
const WARMUP_ITERATIONS: u64 = 1_000;

#[derive(Debug, Clone)]
struct BenchmarkResult {
    profile: &'static str,
    transport: Transport,
    payload_bytes: usize,
    iterations: u64,
    elapsed: Duration,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    ops_per_second: u128,
    bytes_per_second: u128,
    checksum: usize,
}

#[derive(Debug, Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TrafficProfile {
    name: &'static str,
    transport: Transport,
    defaults: &'static [usize],
}

const HTTP_PROFILE: TrafficProfile = TrafficProfile {
    name: "http",
    transport: Transport::Tcp,
    defaults: &[64, 512, 1_200, 4_096, 16_384, 65_527],
};
const VIDEO_PROFILE: TrafficProfile = TrafficProfile {
    name: "video",
    transport: Transport::Udp,
    defaults: &[1_200, 4_096, 16_384, 32_768, 65_527],
};
const MIXED_PROFILE: TrafficProfile = TrafficProfile {
    name: "mixed",
    transport: Transport::Udp,
    defaults: &[64, 512, 1_200, 4_096, 16_384, 65_527],
};

pub fn run(
    iterations: u64,
    payload_spec: Option<&str>,
    profile_spec: &str,
    output: Option<&Path>,
) -> Result<(), String> {
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(format!("benchmark iterations must be between 1 and {MAX_ITERATIONS}"));
    }
    let profiles = parse_profiles(profile_spec)?;
    let mut results = Vec::new();
    for profile in profiles {
        let payloads = payload_spec
            .map(parse_payloads)
            .transpose()?
            .unwrap_or_else(|| profile.defaults.to_vec());
        for (index, payload_bytes) in payloads.into_iter().enumerate() {
            let transport = if profile.name == "mixed" && index % 3 == 0 {
                Transport::Tcp
            } else {
                profile.transport
            };
            results.push(run_payload(iterations, profile.name, transport, payload_bytes)?);
        }
    }
    for result in &results {
        println!(
            "benchmark codec_packet profile={} transport={} payload_bytes={} iterations={} elapsed_ms={:.3} \
             p50_ns={} p95_ns={} p99_ns={} ops_per_second={} bytes_per_second={} checksum={}",
            result.profile,
            result.transport.as_str(),
            result.payload_bytes,
            result.iterations,
            result.elapsed.as_secs_f64() * 1_000.0,
            result.p50_ns,
            result.p95_ns,
            result.p99_ns,
            result.ops_per_second,
            result.bytes_per_second,
            result.checksum
        );
    }
    if let Some(output) = output {
        write_csv(output, &results)?;
        println!("benchmark csv={}", output.display());
    }
    Ok(())
}

fn parse_payloads(spec: &str) -> Result<Vec<usize>, String> {
    let mut payloads = Vec::new();
    for value in spec.split(',') {
        let payload = value
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("benchmark payload size is not an integer: {value}"))?;
        if payload == 0 || payload > 65_527 {
            return Err(format!("benchmark payload size must be between 1 and 65527: {payload}"));
        }
        if !payloads.contains(&payload) {
            payloads.push(payload);
        }
    }
    if payloads.is_empty() || payloads.len() > MAX_PAYLOADS {
        return Err(format!("benchmark payloads must contain 1 to {MAX_PAYLOADS} values"));
    }
    Ok(payloads)
}

fn parse_profiles(spec: &str) -> Result<Vec<TrafficProfile>, String> {
    let mut profiles = Vec::new();
    for value in spec.split(',') {
        let profile = match value.trim() {
            "http" => HTTP_PROFILE,
            "video" => VIDEO_PROFILE,
            "mixed" => MIXED_PROFILE,
            "all" => {
                profiles.extend([HTTP_PROFILE, VIDEO_PROFILE, MIXED_PROFILE]);
                continue;
            }
            other => return Err(format!("unknown benchmark profile: {other}")),
        };
        if !profiles.iter().any(|item| item.name == profile.name) {
            profiles.push(profile);
        }
    }
    if profiles.is_empty() || profiles.len() > 3 {
        return Err("benchmark profiles must contain http, video, mixed, or all".into());
    }
    Ok(profiles)
}

fn run_payload(
    iterations: u64,
    profile: &'static str,
    transport: Transport,
    payload_bytes: usize,
) -> Result<BenchmarkResult, String> {
    let fill = match profile {
        "http" => 0x48,
        "video" => 0x56,
        _ => 0x4d,
    };
    let payload = vec![fill; payload_bytes];
    let mut datagram = Vec::with_capacity(payload_bytes + 8);
    encode_datagram(0, &payload, &mut datagram).map_err(|error| error.to_string())?;
    let capsule = Capsule { capsule_type: 0, value: datagram.clone() };
    let packet = ipv4_fixture(transport, payload_bytes);
    let mut encoded = Vec::with_capacity(payload_bytes + 16);

    for _ in 0..iterations.min(WARMUP_ITERATIONS) {
        black_box(exercise(transport, &capsule, &datagram, &packet, &mut encoded)?);
    }
    let sample_stride = iterations.div_ceil(MAX_LATENCY_SAMPLES).max(1);
    let sample_count = iterations.div_ceil(sample_stride) as usize;
    let mut samples = Vec::with_capacity(sample_count);
    let started = Instant::now();
    let mut checksum = 0usize;
    for iteration in 0..iterations {
        let sample_started = (iteration % sample_stride == 0).then(Instant::now);
        checksum =
            checksum.wrapping_add(exercise(transport, &capsule, &datagram, &packet, &mut encoded)?);
        if let Some(sample_started) = sample_started {
            samples.push(sample_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
        }
    }
    let elapsed = started.elapsed();
    let (p50_ns, p95_ns, p99_ns) = percentiles(&mut samples);
    let elapsed_ns = elapsed.as_nanos().max(1);
    let operations_per_iteration = if matches!(transport, Transport::Udp) { 4 } else { 3 };
    let operations = u128::from(iterations) * operations_per_iteration;
    let ops_per_second = operations.saturating_mul(1_000_000_000) / elapsed_ns;
    let bytes_per_second =
        u128::from(iterations).saturating_mul(payload_bytes as u128).saturating_mul(1_000_000_000)
            / elapsed_ns;
    Ok(BenchmarkResult {
        profile,
        transport,
        payload_bytes,
        iterations,
        elapsed,
        p50_ns,
        p95_ns,
        p99_ns,
        ops_per_second,
        bytes_per_second,
        checksum,
    })
}

fn exercise(
    transport: Transport,
    capsule: &Capsule,
    datagram: &[u8],
    packet: &[u8],
    encoded: &mut Vec<u8>,
) -> Result<usize, String> {
    encoded.clear();
    encode(capsule, encoded).map_err(|error| error.to_string())?;
    let mut decoder = Decoder::new(CapsuleLimits::uniform(65_535));
    let capsules = decoder.push(encoded).map_err(|error| error.to_string())?;
    let decoded = if matches!(transport, Transport::Udp) {
        Some(decode_datagram(datagram).map_err(|error| error.to_string())?)
    } else {
        None
    };
    let packet = PacketView::parse(packet).map_err(|error| error.to_string())?;
    Ok(capsules.len() + decoded.map_or(0, |value| value.payload.len()) + packet.total_len())
}

fn percentiles(samples: &mut [u64]) -> (u64, u64, u64) {
    samples.sort_unstable();
    let value = |percentile: usize| {
        let index = (samples.len().saturating_sub(1) * percentile) / 100;
        samples[index]
    };
    (value(50), value(95), value(99))
}

fn write_csv(path: &Path, results: &[BenchmarkResult]) -> Result<(), String> {
    let commit = std::env::var("MASKMAN_BENCH_COMMIT").unwrap_or_else(|_| "unknown".into());
    let target = std::env::var("MASKMAN_BENCH_TARGET")
        .unwrap_or_else(|_| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS));
    let rust = std::env::var("MASKMAN_BENCH_RUST").unwrap_or_else(|_| "unknown".into());
    let cpu = std::env::var("MASKMAN_BENCH_CPU").unwrap_or_else(|_| "unknown".into());
    let governor = std::env::var("MASKMAN_BENCH_GOVERNOR").unwrap_or_else(|_| "unknown".into());
    let rss_bytes = std::env::var("MASKMAN_BENCH_RSS_BYTES").unwrap_or_else(|_| "unknown".into());
    let mut csv = String::from(
        "commit,target,rust,cpu,governor,rss_bytes,profile,transport,payload_bytes,iterations,\
elapsed_ns,elapsed_ms,ops_per_second,bytes_per_second,p50_ns,p95_ns,p99_ns,checksum,notes\n",
    );
    for result in results {
        csv.push_str(&format!(
            "{commit},{target},{rust},{cpu},{governor},{rss_bytes},{},{},{},{},{},{:.3},{},{},{},{},{},{},codec+packet pipeline; sampled latency; synthetic traffic profile\n",
            result.profile,
            result.transport.as_str(),
            result.payload_bytes,
            result.iterations,
            result.elapsed.as_nanos(),
            result.elapsed.as_secs_f64() * 1_000.0,
            result.ops_per_second,
            result.bytes_per_second,
            result.p50_ns,
            result.p95_ns,
            result.p99_ns,
            result.checksum,
        ));
    }
    fs::write(path, csv)
        .map_err(|error| format!("writing benchmark CSV {}: {error}", path.display()))
}

fn ipv4_fixture(transport: Transport, payload_bytes: usize) -> Vec<u8> {
    let l4_header_bytes = if matches!(transport, Transport::Tcp) { 20 } else { 8 };
    let packet_payload = payload_bytes.min(65_535 - 20 - l4_header_bytes);
    let mut packet = vec![0u8; 20 + l4_header_bytes + packet_payload];
    packet[0] = 0x45;
    let packet_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = if matches!(transport, Transport::Tcp) { 6 } else { 17 };
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

#[cfg(test)]
mod tests {
    use super::{parse_payloads, parse_profiles, HTTP_PROFILE, VIDEO_PROFILE};

    #[test]
    fn payload_parser_deduplicates_and_bounds_values() {
        assert_eq!(parse_payloads("64, 512,64").unwrap_or_default(), vec![64, 512]);
        assert!(parse_payloads("0").is_err());
        assert!(parse_payloads("65528").is_err());
        assert!(parse_payloads("").is_err());
    }

    #[test]
    fn profile_parser_supports_all_and_rejects_unknown() {
        assert_eq!(parse_profiles("all").unwrap_or_default().len(), 3);
        assert_eq!(parse_profiles("http,mixed,http").unwrap_or_default().len(), 2);
        assert!(parse_profiles("icmp").is_err());
    }

    #[test]
    fn default_profiles_cover_mtu_and_large_transfer_sizes() {
        assert!(HTTP_PROFILE.defaults.contains(&64));
        assert!(HTTP_PROFILE.defaults.contains(&65_527));
        assert!(VIDEO_PROFILE.defaults.contains(&32_768));
        assert!(VIDEO_PROFILE.defaults.contains(&65_527));
    }
}

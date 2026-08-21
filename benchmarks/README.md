# Benchmark records

Run the synthetic traffic profiles on a dedicated host:

`cargo run --release -p xtask -- benchmark --iterations 10000000 --profiles http,video,mixed --output benchmarks/baseline.csv`

Profiles model HTTP request/response-sized TCP payloads, video-sized UDP
segments, and a mixed TCP/UDP workload. The default matrix includes 64B, 512B,
1200B, 4KiB, 16KiB, 32KiB, and 65,527B where applicable. Use
`--payloads 64,512,1200,4096,16384,65527` to force a common matrix across
profiles. The benchmark measures the reusable codec and packet parsing
pipeline, with sampled p50/p95/p99 latency, operations per second, and payload
bytes per second. It does not measure QUIC syscalls, kernel forwarding, TUN,
DNS, or real network latency.

These are per-frame payload sizes, not the total size of a Google page or a
YouTube session. Large values stress copy/parse throughput; values above the
path MTU are synthetic batching cases. End-to-end traffic tests must additionally
run long-lived flows with MTU-sized packets, connection concurrency, loss, and
reordering.

Record the exact commit, target triple, Rust toolchain, CPU governor, CPU, RSS,
and host details alongside the CSV. Compare p95/p99 forwarding latency from a
separate real QUIC/network-namespace harness; do not use this synthetic result
as an end-to-end proxy throughput claim.

`baseline.csv` is a checked-in reproducible reference run. Replace it only with
the release command above and set `MASKMAN_BENCH_COMMIT`, `MASKMAN_BENCH_TARGET`,
and `MASKMAN_BENCH_RUST` so rows remain attributable.

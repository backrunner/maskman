# Benchmark records

Run `cargo run --release -p xtask -- benchmark --iterations 10000000` on a
dedicated host and record the exact commit, target triple, Rust toolchain, CPU
governor, payload size, iterations, elapsed time, operations per second, CPU,
and RSS. Keep one row per release and compare p95/p99 forwarding latency from
the real QUIC/namespace harness separately from this codec smoke.

The checked-in `baseline.csv` is a schema template, not a performance claim.

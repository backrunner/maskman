# Maskman fuzz gate

The six protocol targets and the two configuration targets are built from the
standalone `fuzz` manifest. A local smoke run is:

```text
cargo fuzz run capsule_decoder -- -max_total_time=60 -rss_limit_mb=1024 -malloc_limit_mb=64
cargo fuzz run config_toml -- -max_total_time=60 -rss_limit_mb=1024 -malloc_limit_mb=64
```

CI runs every target with a bounded time, a 64 MiB single-allocation limit, and
a 1 GiB process RSS limit. The larger process limit leaves room for sanitizer
quarantine and coverage state; the allocation limit catches target-controlled
length regressions. Preserve new crash artifacts and add the corresponding
regression test before replacing a corpus entry. The checked-in corpus contains
small seeds only; long-running campaign output belongs in CI artifacts.

# Soak test

Use `../../scripts/soak.sh` with a foreground `maskman serve` command and a
temporary configuration. `MASKMAN_SOAK_SECONDS` defaults to 24 hours. The
operator should sample RSS, file descriptors, session counts, journal entries,
and task counts while rotating tokens, reloading configuration, and injecting
packet loss. The script stops the foreground process with SIGTERM after the
window and preserves its exit status.

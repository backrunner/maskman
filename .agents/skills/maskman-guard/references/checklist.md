# Maskman Guard Checklist

Use only the sections relevant to the change. Record exceptions in the change description with evidence and a follow-up issue; do not silently skip a hard stop.

## Protocol

- Confirm the RFC and HTTP version profile.
- Confirm method, protocol, authority, scheme, path, and Capsule-Protocol handling.
- Confirm RFC 9484 wildcard %2A behavior and target/ipproto validation.
- Confirm Context ID 0 semantics, Quarter Stream ID demultiplexing, capsule type and length handling.
- Confirm ADDRESS_ASSIGN, ADDRESS_REQUEST, and ROUTE_ADVERTISEMENT are parsed atomically.
- Confirm malformed, truncated, unknown, oversized, and out-of-order input behavior.
- Add a golden vector or property/fuzz case.

## Server and data plane

- Confirm authentication precedes DNS and resource provisioning.
- Compile request policy once, then enforce it per datagram/packet.
- Bound connections, requests, DNS, queues, memory, sessions, bytes, and idle time.
- Preserve datagram loss semantics and QUIC congestion control.
- Do not hold a lock across await; do not spawn a task per packet.

## Security

- Do not log bearer tokens, Authorization headers, private keys, packet payloads, or unrestricted destinations.
- Check source prefix, destination policy, protocol scope, private ranges, and local addresses.
- Connected UDP sockets are preferred; fallback sockets need per-packet 5-tuple validation.
- IP forwarding must handle extension headers, TTL/Hop Limit, MTU, ICMP isolation, and BCP 38.
- Privileged operations remain in platform code with ownership journal and cleanup.

## Configuration and CLI

- TOML and JSON use the same strict model and schema version.
- Unknown fields fail; relative paths resolve from config directory.
- Secrets are generated with sufficient entropy, displayed once, and never put in argv/history/logs.
- Interactive and non-interactive paths have the same semantic validation.
- Destructive commands have dry-run/confirmation behavior; status has a stable JSON form.

## Update and release

- Target selection is fixed to x86_64 Linux musl, aarch64 Linux musl, or aarch64 macOS as applicable.
- Verify digest and independent signature before staging.
- Reject archive traversal, links escaping the staging root, and oversized files.
- Validate staged binary and configuration before replacement.
- Replace atomically, retain one rollback version, restart, and health-check.
- Add or update supply-chain, checksum, signature, and rollback tests.

## Verification and handoff

- Run cargo fmt --check and targeted tests.
- Run cargo test --workspace when a shared crate or contract changes.
- Run cargo deny check and cargo audit for dependency changes.
- Run quick_validate.py .agents/skills/maskman-guard for skill changes.
- Inspect git diff --check, git status, and the final diff for secrets or unrelated files.
- Commit as BackRunner <dev@backrunner.top> with subject xxx(comp): desc.

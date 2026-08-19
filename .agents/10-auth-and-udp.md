# M3 Authentication and CONNECT-UDP Evidence

## Implemented boundary

The production request path now follows this order:

```text
HTTP/3 request syntax
  -> bearer or mTLS principal
  -> role capability
  -> DNS resolution (only for an authenticated name target)
  -> resolved-address policy
  -> connected UDP socket
  -> 2xx response and bounded forwarding
```

Bearer values use the setup format `mm_<token-id>_<secret>`. Only the
SHA-256 digest is retained in the compiled configuration; comparison uses a
constant-time operation. mTLS uses rustls client-certificate verification when
`tls.client_ca_file` is configured and maps the peer certificate SHA-256 to a
configured principal.

Each session has a connected Tokio UDP socket, a bounded 64-entry ingress and
egress queue, active/new-tunnel quota accounting, and ingress/egress token
buckets. QUIC DATAGRAM is preferred; unsupported peers use the request stream's
DATAGRAM Capsule path. A QUIC `TooLarge` result is dropped rather than silently
re-encoded to hide PMTU failure.

## Verification

```text
cargo test -p maskman-server --locked                         9 passed
cargo clippy --workspace --all-targets --all-features         clean
cargo check --workspace --all-targets                         passed
authenticated_connect_udp_forwards_to_connected_socket       passed
```

The authenticated integration test sends a real HTTP/3 Extended CONNECT with a
bearer credential, forwards a payload through a connected loopback UDP target,
and verifies the response returns on the HTTP Datagram path. Unit tests cover
invalid/expired bearer values, policy denial, queue/rate bounds, and quota
limits.

M3 deliberately does not claim CONNECT-IP, TUN, route mutation, or privileged
platform behavior. Those remain M4/M5 gates.

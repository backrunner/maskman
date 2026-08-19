# M4 CONNECT-IP Evidence

## Implemented boundary

The authenticated request path now supports RFC 9484 over HTTP/3:

~~~
HTTP/3 CONNECT-IP syntax
  -> bearer or mTLS principal
  -> connect-ip capability and ipproto policy
  -> bounded address-pool lease
  -> ADDRESS_ASSIGN response
  -> per-packet source, destination, protocol, MTU, and hop-limit checks
  -> bounded TUN queue
~~~

Each IP session receives host-prefix assignments from the configured IPv4 and/or
IPv6 pools. Leases are released with the request lifecycle and a destination
registry prevents two sessions from owning the same assigned address. Outbound
packets must use an assigned source, match the URI target scope and principal
destination policy, and use an allowed protocol. IPv4 TTL and IPv6 Hop Limit
are decremented exactly once before the packet enters the TUN boundary. Reverse
packets are looked up by assigned destination and are validated again before
being sent to the client.

The transport context exposes one bounded TUN ingress queue and a
dispatch_tun_packet boundary. tun_bridge is the only server-side adapter
that moves packets between this queue and the platform TUN handle; it has a
fixed pair of long-lived tasks and never spawns work per packet.

maskman-platform now owns TUN creation through tun-rs, a resource journal,
and a Linux-only rtnetlink route manager. Route operations record their
destination and interface index before cleanup. No service, firewall, NAT, or
privilege mutation is performed by protocol or request code.

## Verification

~~~
cargo test -p maskman-server --all-targets             17 passed
cargo test -p maskman-platform --all-targets            2 passed
cargo check --workspace --all-targets                  passed
~~~

The HTTP/3 integration test authenticates CONNECT-IP, parses the
ADDRESS_ASSIGN capsule, sends an IPv4 packet over QUIC DATAGRAM, verifies the
packet reaches the TUN queue with TTL 63, injects a reverse packet through the
TUN boundary, and verifies it returns on the same request stream.

Privileged Linux namespace, nftables/NAT, ICMP Packet Too Big generation, and
macOS utun route smoke tests remain M4/M5 release gates. The current platform
implementation deliberately keeps those operations behind explicit adapters
and does not silently mutate host networking during ordinary unit tests.

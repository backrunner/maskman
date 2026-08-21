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
destination policy, and use an allowed protocol. Client-to-TUN decapsulation
preserves IPv4 TTL and IPv6 Hop Limit; reverse packets are decremented exactly
once immediately before HTTP Datagram encapsulation. Locally generated ICMP
errors bypass that decrement because they are not forwarded packets.

The transport context exposes one bounded TUN ingress queue and a
dispatch_tun_packet boundary. tun_bridge is the only server-side adapter
that moves packets between this queue and the platform TUN handle; it has a
fixed pair of long-lived tasks and never spawns work per packet.

maskman-platform now owns TUN creation through tun-rs, a resource journal,
and a Linux-only rtnetlink route manager. Route operations persist their
destination and interface index before mutation, and TUN/NAT/sysctl operations
use the same prepare-before-apply journal contract. The installed service uses
a root supervisor to open listeners and network resources, then passes only
the prepared descriptors to a dedicated worker. No service, firewall, NAT, or
privilege mutation is performed by protocol or request code.

## Verification

~~~
cargo test -p maskman-server --all-targets             local suite passed
cargo test -p maskman-platform --all-targets            local suite passed
cargo check --workspace --all-targets                  passed
~~~

The HTTP/3 integration test authenticates CONNECT-IP, parses the
ADDRESS_ASSIGN capsule, sends an IPv4 packet over QUIC DATAGRAM, verifies the
packet reaches the TUN queue with its original TTL, injects a reverse packet
through the TUN boundary, and verifies it returns on the same request stream
with one TTL decrement.

The protocol layer also bounds ADDRESS_REQUEST IDs and route tables, rejects
literal prefixes that have no policy intersection before leasing resources,
and emits bounded IPv4/IPv6 ICMP errors for policy and routing failures.

The runtime control plane now provides a versioned local `status`/`reload`
protocol, generation-aware atomic config swaps, bounded Prometheus text
metrics, and live connection/session/packet counters. Linux managed NAT is
implemented behind an ownership-marked nftables table; macOS has dedicated
route and pf-anchor adapters. Journal loading rejects symlinks, broad file
permissions, foreign interface names, and foreign NAT identifiers before any
cleanup mutation.

Privileged Linux namespace forwarding, production supervisor/worker fd
passing, ICMP Packet Too Big delivery under a real PMTU, and macOS utun/pf
route smoke tests remain M4/M5 release gates. Platform mutation remains behind
explicit adapters and is never exercised by ordinary unit tests.

# Maskman threat model review

## Assets and boundaries

- Bearer token hashes, mTLS trust roots, release verification key, and config
  files are operator secrets or trust anchors.
- The QUIC/H3 listener is an untrusted network boundary. Request headers,
  capsule bytes, URI paths, DNS answers, and IP packets are attacker input.
- The worker boundary separates protocol state and packet forwarding from the
  root supervisor when the installed service sets `MASKMAN_ROLE=supervisor`.
  The supervisor opens listeners/TUN, persists ownership, clears inheritance
  only for the hand-off descriptors, and starts the worker as the dedicated
  `maskman` identity. The worker applies `no_new_privs`/non-dumpable state.
  Foreground development mode remains an explicit same-process path and is
  not treated as the production privilege boundary.
  TUN, routes, firewall/NAT, service files, and privileges are platform-owned
  resources and must be represented in a journal.
- GitHub release metadata is an availability input; artifact trust comes only
  from the compiled Ed25519 key and checksum verification.

## Abuse paths and controls

| Abuse path | Control | Evidence |
| --- | --- | --- |
| Unauthenticated proxy request | Header validation and auth before DNS/socket/TUN | server auth and transport tests |
| Private or management network access | Default deny classifier plus role ACL and per-packet checks | protocol scope and policy tests |
| Source spoofing or cross-session packet leak | Assigned-prefix validation and destination registry | CONNECT-IP tests |
| Capsule length or queue memory amplification | Bounded decoder, TUN queue, token buckets, and quotas | codec properties and data-plane tests |
| Resource orphan after crash | Ownership journal, strict journal validation, reverse cleanup, explicit cleanup command | platform journal tests; privileged gate pending |
| Release replacement with malicious asset | Fixed target, HTTPS, SHA-256, independent Ed25519, staged checks, rollback | update unit tests |
| Secret disclosure in diagnostics | Hash-only config, one-time token output, redacted status | CLI/auth review |
| Root worker compromise | Supervisor/worker split, inherited-fd allowlist, privilege drop, no-new-privileges | local implementation/tests; target service evidence pending |
| Misleading health or reload state | Versioned local control protocol, atomic generation checks, metrics, and real bounded counters | local control tests; target service validation pending |

## Residual risk and required gates

Managed NAT, macOS route/pf adapters, and the supervisor/worker fd boundary now
have local implementations, but require privileged target validation. Linux
namespace Maskman forwarding, independent MASQUE and mTLS
interoperability, and the 24-hour soak also require target runner evidence.
These are release blockers tracked in `release/checklist.md`; changing their
status in documentation is not a substitute for implementation or a real run.

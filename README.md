# Maskman

Maskman is an HTTP/3-only MASQUE proxy implementation for CONNECT-IP and
CONNECT-UDP, with authenticated policy enforcement and bounded resource use.

The project is under active development. The current release profile and
evidence are documented in [.agents/README.md](.agents/README.md); HTTP/1.1
and HTTP/2 are intentionally outside the v1 profile.

## Quick Start

### Server install

The one-click installer supports Debian/Ubuntu, RHEL/Fedora/CentOS/Rocky/Alma,
Arch/Manjaro, and Apple Silicon macOS. Linux uses systemd; macOS uses a
system launchd daemon. It creates the dedicated `maskman` service identity,
generates a first bearer-authenticated development configuration, installs the
native service, starts it, and prints the credential in a terminal panel.

The installer verifies both the SHA-256 digest and detached Ed25519 signature
before installing a release. Its Ed25519 trust anchor is pinned in the reviewed
installer source. A production release must publish the matching `.sig` asset;
there are no release artifacts until the release checklist is complete.

Download the script first so it can be inspected before running it:

```sh
curl --fail --location --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/backrunner/maskman/main/scripts/install.sh \
  --output maskman-install.sh
chmod 0755 maskman-install.sh
sudo ./maskman-install.sh --color auto
```

For a reproducible install, pin an exact published release:

```sh
sudo ./maskman-install.sh --version 0.1.0 --color auto
```

The panel prints a token in the form `mm_<id>_<secret>`. Store it immediately;
the secret is shown only when a new configuration is created and cannot be
recovered from the configuration file. Check the daemon with:

```sh
sudo /usr/local/bin/maskman \
  --config /etc/maskman/config.toml status
```

On macOS, use `/Library/Application Support/Maskman/config.toml` as the config
path. `--dry-run` prints the detected platform and paths without downloading
or changing the system. `--force` replaces an existing configuration and
credentials and should only be used deliberately.

The installer starts with CONNECT-UDP and a self-signed development
certificate. Before exposing the daemon to the Internet, replace the TLS
certificate and private-key paths with production credentials, then run
`maskman config validate` and restart the service. The default policy denies
private, loopback, link-local, multicast, broadcast, and management
destinations.

### Build from source

For local development without a system daemon:

```sh
cargo run --locked -p maskman -- setup \
  --development --non-interactive --yes --enable-udp \
  --output ./config.toml
cargo run --locked -p maskman -- \
  --config ./config.toml config validate
cargo run --locked -p maskman -- \
  --config ./config.toml serve
```

The setup command prints the bearer credential once. Development TLS is
intended for local testing only.

### Surge MASQUE client

Surge iOS 5.22+ and macOS 6.9+ support the standard MASQUE policy. Maskman
accepts Surge's HTTP Basic credentials by mapping the token ID to `username`
and the token secret to `password`. Given a setup credential in the form
`mm_<id>_<secret>`, use:

```ini
[Proxy]
Maskman = masque, proxy.example.com, 443, username=<id>, password=<secret>, sni=proxy.example.com

[Proxy Group]
Default = select, Maskman
```

Use a certificate trusted by the device. For development-only testing with a
self-signed certificate, add `skip-cert-verify=true` to the policy and do not
expose that configuration to the Internet. Surge's UDP relay uses CONNECT-UDP
and HTTP Datagrams automatically; the server must have `proxy.udp.enabled =
true` and the token's role must include `connect-udp`.

The endpoint path is Maskman's standard `/.well-known/masque` base path. A
Surge device test is still required for an interoperability record; the
server-side Basic credential mapping is covered by `maskman-server` tests.

### Service lifecycle

The installer delegates service ownership and hardening to the platform-aware
CLI. The same lifecycle commands can be used after a manual setup:

```sh
sudo maskman --config /etc/maskman/config.toml install --yes
sudo maskman --config /etc/maskman/config.toml start --yes
sudo maskman --config /etc/maskman/config.toml status --json
```

The release target matrix currently contains Linux x86_64, Linux arm64, and
Apple Silicon macOS. Intel macOS is not included in the published artifacts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

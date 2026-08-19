# Maskman operator runbook

This runbook applies to the single `maskman` binary and the HTTP/3-only v1
profile. It does not treat a draft GitHub release or a skipped privileged job
as production evidence.

## Start safely

1. Validate the exact configuration used by the service:

   ```text
   maskman --config /etc/maskman/config.toml config validate --check-system
   ```

2. Preview service changes, then install with an explicit confirmation:

   ```text
   maskman --config /etc/maskman/config.toml install --dry-run
   maskman --config /etc/maskman/config.toml install --yes
   maskman --config /etc/maskman/config.toml start --yes
   ```

3. Confirm the service and configuration hash. Use `--json` for monitoring:

   ```text
   maskman --config /etc/maskman/config.toml status --json
   ```

`serve` is the foreground development path. It does not install a service or
fork a supervisor.

## Diagnose a failed start

- Run `config validate --check-system` first; it checks certificate paths,
  authentication, policy, TUN prerequisites, and managed-NAT availability.
- Inspect `status --json` for `installed`, `running`, `pid`, `config.hash_sha256`,
  and the service manager detail. Do not paste bearer tokens or private keys into
  an issue.
- If a previous process owns the journal, stop the service and inspect before
  removing anything:

  ```text
  maskman --config /etc/maskman/config.toml cleanup --dry-run
  maskman --config /etc/maskman/config.toml cleanup --yes
  ```

- A failed CONNECT request should expose only its `Proxy-Status` error token;
  server logs must not contain the Authorization value or packet payload.

## Rotate or revoke credentials

Create a replacement token, record the one-time output in a protected secret
store, reload, then revoke the old public ID:

```text
maskman --config /etc/maskman/config.toml auth token create --yes --reload
maskman --config /etc/maskman/config.toml auth token list --json
maskman --config /etc/maskman/config.toml auth token revoke tok_old --yes --reload
```

The configuration stores only a SHA-256 digest of the bearer secret. `list`
never prints the secret.

## Upgrade and rollback

First perform a signed metadata check without changing the binary:

```text
maskman --config /etc/maskman/config.toml update --check
maskman --config /etc/maskman/config.toml update --yes
```

The updater fixes the target triple, requires HTTPS, verifies the SHA-256 file
and compiled Ed25519 key, rejects unsafe archive entries, validates the staged
`--version` and configuration, and keeps one backup at
`<binary-path>.previous`. If service health fails after replacement it restores
that backup and restarts the service. Keep the failed output and service status
before retrying; do not manually delete the backup.

A source build without `MASKMAN_RELEASE_PUBLIC_KEY_HEX` fails closed and cannot
self-update. Release automation also rejects the public RFC 8032 test key.

## Stop and collect evidence

```text
maskman --config /etc/maskman/config.toml stop --yes
maskman --config /etc/maskman/config.toml status --json
```

For a release record, attach the exact commit, target triple, toolchain,
configuration hash, service-manager output, journal state, and whether the
Linux namespace, macOS arm64 privileged, independent MASQUE, and 24-hour soak
gates actually ran. A skipped or unavailable gate remains a blocker.

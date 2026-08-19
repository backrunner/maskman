# macOS arm64 platform smoke

Run `../../scripts/macos-arm64-smoke.sh` on an arm64 macOS runner. The script
always runs unprivileged platform tests first. With
`MASKMAN_PRIVILEGED_SMOKE=1`, it additionally verifies that a signed runner has
utun prerequisites. Creation, route mutation, pf anchoring, and real forwarding
are still release blockers; a missing entitlement or device is reported as
`SKIP`, never as a false pass.

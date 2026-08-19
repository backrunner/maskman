#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    echo "SKIP macOS arm64 smoke: an arm64 macOS runner is required"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
fi
cargo test --locked -p maskman-platform
if [ "${MASKMAN_PRIVILEGED_SMOKE:-0}" != "1" ]; then
    echo "SKIP privileged utun smoke: set MASKMAN_PRIVILEGED_SMOKE=1 on the signed runner"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
fi
if ! ifconfig -l | tr ' ' '\n' | grep '^utun' >/dev/null 2>&1; then
    echo "SKIP privileged utun smoke: no utun device is currently available"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
fi
echo "READY macOS arm64 utun smoke prerequisites; full route/pf forwarding remains a release gate"

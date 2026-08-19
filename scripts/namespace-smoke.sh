#!/bin/sh
set -eu

if [ "${MASKMAN_NETWORK_NAMESPACE:-0}" != "1" ]; then
    echo "SKIP network namespace smoke: set MASKMAN_NETWORK_NAMESPACE=1"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(id -u)" -ne 0 ]; then
    echo "SKIP network namespace smoke: Linux root or CAP_NET_ADMIN is required"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
fi
command -v ip >/dev/null 2>&1 || {
    echo "SKIP network namespace smoke: iproute2 is unavailable"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
}
command -v ping >/dev/null 2>&1 || {
    echo "SKIP network namespace smoke: ping is unavailable"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
}
command -v sysctl >/dev/null 2>&1 || {
    echo "SKIP network namespace smoke: sysctl is unavailable"
    [ "${MASKMAN_REQUIRE_PRIVILEGED_SMOKE:-0}" = "1" ] && exit 78
    exit 0
}

suffix=$$
client_ns="maskman-client-${suffix}"
proxy_ns="maskman-proxy-${suffix}"
target_ns="maskman-target-${suffix}"
cleanup() {
    ip netns del "$client_ns" 2>/dev/null || true
    ip netns del "$proxy_ns" 2>/dev/null || true
    ip netns del "$target_ns" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
ip netns add "$client_ns"
ip netns add "$proxy_ns"
ip netns add "$target_ns"
ip link add "mmc-${suffix}" type veth peer name "mmp-${suffix}"
ip link set "mmc-${suffix}" netns "$client_ns"
ip link set "mmp-${suffix}" netns "$proxy_ns"
ip link add "mmt-${suffix}" type veth peer name "mmp2-${suffix}"
ip link set "mmt-${suffix}" netns "$target_ns"
ip link set "mmp2-${suffix}" netns "$proxy_ns"
for namespace in "$client_ns" "$proxy_ns" "$target_ns"; do
    ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.accept_dad=0
    ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.default.accept_dad=0
done
ip -n "$client_ns" addr add 192.0.2.2/30 dev "mmc-${suffix}"
ip -n "$proxy_ns" addr add 192.0.2.1/30 dev "mmp-${suffix}"
ip -n "$target_ns" addr add 198.51.100.2/30 dev "mmt-${suffix}"
ip -n "$proxy_ns" addr add 198.51.100.1/30 dev "mmp2-${suffix}"
ip -n "$client_ns" -6 addr add 2001:db8:1::2/64 dev "mmc-${suffix}"
ip -n "$proxy_ns" -6 addr add 2001:db8:1::1/64 dev "mmp-${suffix}"
ip -n "$target_ns" -6 addr add 2001:db8:2::2/64 dev "mmt-${suffix}"
ip -n "$proxy_ns" -6 addr add 2001:db8:2::1/64 dev "mmp2-${suffix}"
ip -n "$client_ns" link set lo up
ip -n "$proxy_ns" link set lo up
ip -n "$target_ns" link set lo up
ip -n "$client_ns" link set "mmc-${suffix}" up
ip -n "$proxy_ns" link set "mmp-${suffix}" up
ip -n "$proxy_ns" link set "mmp2-${suffix}" up
ip -n "$target_ns" link set "mmt-${suffix}" up
ip -n "$client_ns" route add 198.51.100.0/30 via 192.0.2.1
ip -n "$target_ns" route add 192.0.2.0/30 via 198.51.100.1
ip -n "$client_ns" -6 route add 2001:db8:2::/64 via 2001:db8:1::1
ip -n "$target_ns" -6 route add 2001:db8:1::/64 via 2001:db8:2::1
ip netns exec "$proxy_ns" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$proxy_ns" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec "$client_ns" ping -c 1 -W 2 198.51.100.2 >/dev/null
ip netns exec "$client_ns" ping -6 -c 1 -W 2 2001:db8:2::2 >/dev/null
echo "READY dual-stack network namespace topology and routed ping client=$client_ns proxy=$proxy_ns target=$target_ns"
echo "NOTE this proves isolated topology routing, not Maskman TUN/session forwarding"
if [ "$#" -gt 0 ]; then
    ip netns exec "$proxy_ns" "$@"
else
    echo "No proxy command supplied; topology setup only"
fi

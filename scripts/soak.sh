#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: MASKMAN_SOAK_SECONDS=86400 $0 <maskman command> [args...]" >&2
    exit 2
fi
duration=${MASKMAN_SOAK_SECONDS:-86400}
interval=${MASKMAN_SOAK_SAMPLE_SECONDS:-60}
grace=${MASKMAN_SOAK_GRACE_SECONDS:-30}
case "$duration:$interval:$grace" in
    *[!0-9:]*) echo "soak durations must be positive integer seconds" >&2; exit 2 ;;
esac
if [ "$duration" -eq 0 ] || [ "$interval" -eq 0 ] || [ "$grace" -eq 0 ]; then
    echo "soak durations must be greater than zero" >&2
    exit 2
fi
"$@" &
pid=$!
# shellcheck disable=SC2329 # Invoked indirectly by trap.
cleanup() {
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
started=$(date +%s)
completed=0
while kill -0 "$pid" 2>/dev/null; do
    now=$(date +%s)
    elapsed=$((now - started))
    rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)
    printf 'soak elapsed_seconds=%s pid=%s rss_kb=%s\n' "$elapsed" "$pid" "${rss_kb:-unknown}"
    if [ "$elapsed" -ge "$duration" ]; then
        completed=1
        break
    fi
    remaining=$((duration - elapsed))
    if [ "$remaining" -lt "$interval" ]; then
        sleep "$remaining"
    else
        sleep "$interval"
    fi
done
if [ "$completed" -eq 1 ]; then
    kill -TERM "$pid" 2>/dev/null || true
    waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$grace" ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "soak daemon did not stop within ${grace}s" >&2
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        trap - EXIT INT TERM
        exit 1
    fi
fi
set +e
wait "$pid"
status=$?
set -e
trap - EXIT INT TERM
printf 'soak complete elapsed_seconds=%s exit_status=%s\n' "$(($(date +%s) - started))" "$status"
exit "$status"

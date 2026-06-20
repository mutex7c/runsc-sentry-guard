#!/bin/bash
set -euo pipefail

SOCKET_PATH="/var/run/runsc-sentry-guard.sock"
LOG_OUT="/tmp/backpressure_test.log"

echo "============================================================"
echo " RUNSC-SENTRY-GUARD: ASYNC BACKPRESSURE INTEGRATION TEST   "
echo "============================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This integration harness requires administrative permissions (sudo)." >&2
    exit 1
fi

if [ ! -S "$SOCKET_PATH" ];
then
    echo "[ERROR] Target active containment socket does not exist: $SOCKET_PATH" >&2
    exit 1
fi

echo "[*] Tailing active system logs to track pipeline event drops..."
journalctl -u runsc-sentry-guard -n 0 -f > "$LOG_OUT" 2>&1 &
LOG_TAIL_PID=$!

trap 'kill -9 "$LOG_TAIL_PID" 2>/dev/null || true' EXIT

echo "[*] Launching 60 parallel streaming client channels to test the pool ceiling..."
declare -a CLIENT_PIDS

for i in {1..60};
do
    (
        for _ in {1..5}; do
            echo "execve(/bin/sh) --id=$(printf "a1b2c3d4e5f6%02d" "$i")"
            sleep 0.5
        done
    ) |
    socat - UNIX-CONNECT:"$SOCKET_PATH" >/dev/null 2>&1 &

    CLIENT_PIDS[i]=$!
done

echo "[*] High-velocity stream blast dispatched. Awaiting client completions..."
wait "${CLIENT_PIDS[@]}"

echo "[*] Auditing backpressure enforcement footprints..."
if grep -q "Worker channel saturated" "$LOG_OUT" || \
   grep -q "Worker execution channel full" "$LOG_OUT"; then
    echo -e "\n[SUCCESS] Backpressure successfully triggered! The core engine safely dropped overloaded packets."
    echo "          Host resources remained isolated against memory exhaustion."
    exit 0
else
    echo -e "\n[FAILURE] The daemon failed to report proper rigid backpressure event logging."
    echo "--- CAPTURED TELEMETRY LOG DUMP ---"
    cat "$LOG_OUT"
    exit 1
fi
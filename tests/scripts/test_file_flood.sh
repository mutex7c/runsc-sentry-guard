#!/bin/bash
set -e

LOG_FILE="/var/log/gvisor/flood_test_$(date +%s).boot"
echo "[*] Launching Sequential File Ingestion Flood..."
touch "$LOG_FILE"

# Generates 100,000 unique spoofed signatures instantly
seq 1 100000 | awk '{printf "execve(/bin/sh) --id=%012d\n", $1}' > "$LOG_FILE"

echo "[*] Flood complete. Awaiting daemon ingestion..."
#!/bin/bash
set -euo pipefail

echo "============================================================"
echo " runsc-sentry-guard: Integration Smoke Test                 "
echo "============================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This smoke test requires root privileges (sudo) to bind to Docker and read raw logs." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1;
then
    echo "[ERROR] Docker is not installed or available in PATH." >&2
    exit 1
fi

echo "[*] Building release binary..."
cargo build --release

TEST_DIR="/tmp/runsc_smoke_test_$(date +%s)"
LOG_DIR="${TEST_DIR}/logs"
CONF_FILE="${TEST_DIR}/config.toml"
RULES_FILE="${TEST_DIR}/rules.json"
DAEMON_OUT="${TEST_DIR}/daemon.log"

mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"
chown root:root "$LOG_DIR"

cat << EOF > "$CONF_FILE"
[monitor]
mode = "file"
log_dir = "${LOG_DIR}"
docker_socket_path = "/var/run/docker.sock"
check_interval_ms = 500
ip_whitelist = ["127.0.0.1/32"]
nftables_default_table = "inet filter"
json_logging_enabled = true
systemd_watchdog_interval_ms = 0
flush_firewall_on_shutdown = false
max_workers = 10
security_manifest_paths = ["${RULES_FILE}"]
EOF

cat << 'EOF' > "$RULES_FILE"
{
  "playbooks": {
    "smoke_remediation": {
      "try_actions": [
        { "type": "log_json" }
      ],
      "final_actions": [
        { "type": "log_critical" }
      ]
    }
  },
  "rules": [
    {
      "name": "smoke_test_reverse_shell",
      "match_any": [
        " execve\\(.*(nc)"
      ],
      "playbook": "smoke_remediation"
    }
  ]
}
EOF

echo "[*] Spinning up target ephemeral container..."
CONTAINER_ID=$(docker run -d --rm alpine sleep 300)
echo "[*] Target Container ID: ${CONTAINER_ID}"

echo "[*] Booting runsc-sentry-guard daemon..."
./target/release/runsc-sentry-guard "$CONF_FILE" > "$DAEMON_OUT" 2>&1 &
DAEMON_PID=$!

sleep 2

BOOT_FILE="${LOG_DIR}/${CONTAINER_ID}.boot"
echo "[*] Simulating gVisor payload injection at ${BOOT_FILE}..."
touch "$BOOT_FILE"
echo "execve(/bin/nc) --id=${CONTAINER_ID}" >> "$BOOT_FILE"

sleep 2

echo "[*] Tearing down environment..."
kill -SIGTERM "$DAEMON_PID" || true
wait "$DAEMON_PID" 2>/dev/null || true
docker rm -f "$CONTAINER_ID" >/dev/null

echo "[*] Evaluating SIEM output..."
if grep -q '"action_executed":"log_json"' "$DAEMON_OUT" && grep -q '"component":"worker_engine"' "$DAEMON_OUT";
then
    echo "[SUCCESS] Daemon successfully intercepted the payload, resolved the context, and emitted structured JSON telemetry!"
    rm -rf "$TEST_DIR"
    exit 0
else
    echo "[FAIL] Daemon failed to intercept or process the attack signature."
    echo "--- DAEMON OUTPUT DUMP ---"
    cat "$DAEMON_OUT"
    rm -rf "$TEST_DIR"
    exit 1
fi
# Integration Testing & Threat Simulation Playbook

This document outlines the standard operating procedures for verifying the `runsc-sentry-guard` containment engine. Because this daemon operates at the host edge and mutates system state (firewalls, process execution), these tests must be executed in an isolated staging environment or a designated ephemeral virtual machine.

## 1. Prerequisites & Environment Setup

Ensure your staging host mimics a production configuration:
* Root access (`sudo`) is required.
* `docker` or `podman` must be installed and active.
* `nftables` must be installed.
* The guard daemon must be compiled in release mode and actively running via systemd.

To monitor the daemon's reaction in real-time during these tests, leave a terminal window open tailing the system journal:
```bash
sudo journalctl -u runsc-sentry-guard -f
```

## 2. Test Scenarios

### Scenario A: API Exhaustion & ID Spoofing Flood (Anti-DoS)

**Objective:** Verify that the Token Bucket rate limiter and Negative Cache successfully intercept a massive flood of spoofed container IDs without saturating the Docker API or locking the worker threads.

**Execution:**
Run this bash script to violently flood the ingestion directory with 5,000 unique, malformed container IDs containing a malicious shell signature.

```bash
#!/bin/bash
echo "[TEST] Initiating API Exhaustion Flood..."
for i in {1..5000}; do
  # Generate a sequential padded ID (e.g., 000000000001)
  FAKE_ID=$(printf "%012d" "$i")
  echo "execve(/bin/sh) --id=${FAKE_ID}" >> /var/log/gvisor/flood_test.boot
done
echo "[TEST] Flood complete."
```

**Expected Result:**

1. The journal should log a few initial synchronous lookups.
2. The engine should rapidly log `[WARN] ... Container lookup token pool exhausted. Payload discarded.`.
3. The daemon must **not** crash, and the host CPU/Memory should remain stable, proving the `AntiDosState` logic successfully absorbed the flood.

### Scenario B: UDS Trust Boundary (SO_PEERCRED Verification)

**Objective:** Verify that unprivileged local processes (e.g., a container escapee) cannot inject fabricated telemetry directly into the Unix Domain Socket to trigger false-positive isolations.

**Execution:**
Switch to a standard, non-root user account and attempt to write directly to the daemon's UDS socket utilizing `socat`.

```bash
# Switch to an unprivileged user
su - unprivileged_user

# Attempt to stream a fake payload to the protected socket
echo 'execve(/bin/nc) --id=valid_container_id_here' | socat - UNIX-CONNECT:/var/run/runsc-sentry-guard.sock
```

**Expected Result:**

1. The `socat` connection should be instantly terminated.
2. The journal must log `[WARN] ... Unauthorized UID <number> attempted UDS connection. Payload dropped.`.

### Scenario C: Firewall Subprocess Tokenization

**Objective:** Verify that the `nftables` mitigation playbook correctly parses multi-word table namespaces (like `"inet security_ops"`) and successfully drops malicious IPs without crashing `execve`.

**Execution:**

1. Ensure `config.toml` has `nftables_default_table = "inet filter"`.
2. Launch a real, disposable gVisor container.
3. Manually trigger a malicious signature inside the container's namespace:

```bash
# Get the container ID
CID=$(docker run -d --runtime=runsc alpine sleep 3600)

# Simulate a malicious interactive shell launch
docker exec $CID /bin/sh -c "nc -l -p 4444"
```

**Expected Result:**

1. The daemon intercepts the `execve` launch.
2. The journal should log `[CRITICAL] ... Target network isolated via set container_blacklist ...`.
3. Execute `sudo nft list ruleset` on the host; you must see the container's IP dynamically appended to the blacklist set. The daemon must remain active.

### Scenario D: Double-Checked Locking (OOM Prevention)

**Objective:** Verify that the worker registry caps thread spawning at the `MAX_WORKERS` ceiling (100 threads) to prevent out-of-memory (OOM) host crashes.

**Execution:**
This requires configuring a mock rule that executes a long-running `run_custom_script` (e.g., a script containing `sleep 10`). Trigger that rule simultaneously across 105 distinct, valid container contexts.

**Expected Result:**

1. The first 100 threads are allocated.
2. The journal should log `[CRITICAL] ... Maximum worker thread ceiling reached. Malicious ID flood detected. Payload dropped.` for the final 5 payloads.

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

**Execution:** Run this bash script to violently flood the ingestion directory with 5,000 unique, malformed container IDs containing a malicious shell signature.

```bash
#!/bin/bash
echo "[TEST] Initiating API Exhaustion Flood..."
for i in {1..5000}; do
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

**Execution:** Switch to a standard, non-root user account and attempt to write directly to the daemon's UDS socket utilizing `socat`.

```bash
su - unprivileged_user
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
CID=$(docker run -d --runtime=runsc alpine sleep 3600)
docker exec $CID /bin/sh -c "nc -l -p 4444"
```

**Expected Result:**

1. The daemon intercepts the `execve` launch.
2. The journal should log `[CRITICAL] ... Target network isolated via set container_blacklist ...`.
3. Execute `sudo nft list ruleset` on the host; you must see the container's IP dynamically appended to the blacklist set. The daemon must remain active.

### Scenario D: Double-Checked Locking (OOM Prevention)

**Objective:** Verify that the worker registry caps thread spawning at the `MAX_WORKERS` ceiling (100 threads) to prevent out-of-memory (OOM) host crashes.

**Execution:** This requires configuring a mock rule that executes a long-running `run_custom_script` (e.g., a script containing `sleep 10`). Trigger that rule simultaneously across 105 distinct, valid container contexts.

**Expected Result:**

1. The first 100 threads are allocated.
2. The journal should log `[CRITICAL] ... Maximum worker thread ceiling reached. Malicious ID flood detected. Payload dropped.` for the final 5 payloads.

### Scenario E: The Reconnection State Drift (Race Condition Test)

**Objective:** Verify the daemon's resilience and state synchronization when the out-of-band UDS connection to the container engine drops unexpectedly while workloads are mutating.

**Execution:**

1. Start the daemon with `mode = "socket"` or `mode = "dual"`.
2. Launch a script that rapidly starts and stops 20 benign containers in a tight loop.
3. Concurrently, forcefully restart the host Docker daemon (`sudo systemctl restart docker`) to abruptly sever the UDS stream.
4. Once Docker is back online, trigger a malicious signature inside a newly spawned gVisor container.

**Expected Result:**

1. The daemon journal must log the UDS connection failure and its subsequent 1-second retry attempts without panicking.
2. Upon reconnection, the daemon must successfully intercept the malicious signature in the new container without dropping the payload due to an outdated internal ID cache.

### Scenario F: The Initialization Blind Spot Window

**Objective:** Measure the exact vulnerability window between a container's creation and the daemon's `$O(1)$` cache validation during the `check_interval_ms` window.

**Execution:**

1. Ensure the daemon is running with a high `check_interval_ms` (e.g., `5000` ms) to artificially widen the polling window.
2. Execute a single command that creates a container and immediately triggers a known malicious signature within the same millisecond:

```bash
docker run --rm --runtime=runsc alpine sh -c "nc -l -p 4444"
```

**Expected Result:**

1. The journal must provide clear telemetry on whether the payload was caught.
2. If the payload is captured, verify whether it was resolved via the primary cache (meaning the UDS stream beat the file tailer) or if it required a synchronous fallback lookup via the Anti-DoS queue. If it is dropped, this establishes the strict baseline latency required for production `check_interval_ms` tuning.

### Scenario G: Graceful Shutdown & Configuration-Driven Firewall Flush

**Objective:** Verify that the daemon hooks native OS signals (`SIGINT`, `SIGTERM`) cleanly, terminates ingest workers without leaking state loops, and conditionally purges host `nftables` isolation rules according to configuration profiles.

**Execution:**

1. Provision `config.toml` to declare `flush_firewall_on_shutdown = true`.
2. Generate an active incident context using Scenario C to populate a target blacklist set inside `nftables`.
3. Forcefully dispatch a termination signal command directly straight onto the active process handle:

```bash
sudo systemctl stop runsc-sentry-guard
```

**Expected Result:**

1. The engine journal must cleanly output `[INFO] ... Decommissioning sequence initialized. Processing cleanup contexts.`.
2. The daemon must exit with status `0` without leaving hanging background socket listeners or thread leaks behind.
3. Query `sudo nft list ruleset` on the host processor interface; the target isolation blacklist set elements must be entirely cleared out, confirming the completion of the configuration-driven post-termination purge.

### Scenario H: Cross-Container Mitigation Spoofing Prevention

**Objective:** Verify that the file log engine derives container IDs strictly from the immutable log filename stem rather than untrusted text payloads printed within the logs, ensuring a compromised container cannot frame an adjacent workload.

**Execution:**
1. Generate an active dummy log target profile using a valid, distinct hex name:
```bash
   touch /var/log/gvisor/a1b2c3d4e5f6.boot
```

2. Write an explicit, spoofed system call sequence designed to deliberately target an innocent container ID (`999999999999`):

```bash
   echo "execve(/bin/sh) --id=999999999999" >> /var/log/gvisor/a1b2c3d4e5f6.boot
```

**Expected Result:**

1. The daemon intercepts the malicious signature match.
2. The engine journal must report mitigation execution mapping **strictly** to the file segment name context (`a1b2c3d4e5f6`) rather than executing actions on the malicious injected text payload (`999999999999`).
3. The forged cross-container attack vector is completely neutralized.

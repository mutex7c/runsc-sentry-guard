# Configuration Schema Blueprint

The `runsc-sentry-guard` daemon ingests a declarative TOML file layout. The internal engine enforces strict schema validation at initialization; any unexpected properties or malformed parameters will immediately cause a safe startup abort.

## 1. Global Daemon Parameters (`[monitor]`)

| Parameter Name                 | Data Type Expected                         | Description / Purpose                                                                                                                           |
|:-------------------------------|:-------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                         | String (`"file"`, `"socket"`, or `"dual"`) | Dictates the ingestion strategy. `file` tails disk logs, `socket` listens out-of-band via UDS, and `dual` aggregates both loops simultaneously. |
| `log_dir`                      | String (File Path)                         | The absolute host folder path where gVisor emits its active sandbox `.boot` streams.                                                            |
| `docker_socket_path`           | String (File Path)                         | The absolute path to the container engine IPC socket (e.g., `/var/run/docker.sock` or `/run/podman/podman.sock`).                               |
| `check_interval_ms`            | Unsigned 64-bit Integer                    | The thread polling interval cadence for inspecting file modifications.                                                                          |
| `ip_whitelist`                 | Array of CIDR Strings                      | Core infrastructure IP networks strictly protected against accidental firewall locks.                                                           |
| `nftables_default_table`       | String                                     | The specific nftables table space namespace where containment sets are deployed.                                                                |
| `json_logging_enabled`         | Boolean Flag                               | Toggles terminal output logs between clean plain-text and structured SIEM JSON payloads.                                                        |
| `systemd_watchdog_interval_ms` | Unsigned 64-bit Integer                    | The periodic runtime heartbeat loop frequency for systemd deadlock health checks.                                                               |

> ⚠️ **SECURITY WARNING: Ingestion Modes**
> 
> While `mode = "file"` is supported for legacy setups or lightweight testing environments, 
> it inherently relies on host disk polling. This introduces a slight latency window 
> (Time-of-Check to Time-of-Use) and a theoretical log spoofing risk if an attacker manages 
> to compromise the `/var/log/gvisor/` directory permissions.
>
> The daemon enforces strict directory auditing and mandatory state validation to mitigate 
> this, but **for all production deployments, `mode = "socket"` is strictly recommended** 
> to guarantee sub-millisecond, tamper-proof, out-of-band mitigation.
 
## 2. Container Runtime Engine Configuration (`daemon.json`)

For `runsc-sentry-guard` to receive high-fidelity system call telemetry out-of-band, you must configure Docker/Podman to instruct the runsc / gVisor supervisor to emit strace logs down to the host file system.

Append or merge the following configuration block into your global `/etc/docker/daemon.json` file:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--strace=true",
        "--strace-syscalls=execve,setns,unshare",
        "--debug-log=/var/log/gvisor/"
      ]
    }
  }
}
```

### 2.1 Argument Breakdown

* **`--strace=true`**: Enforces system call tracing on the sandboxed container kernel ring.
* **`--strace-syscalls=execve,setns,unshare`**: Filters tracing strictly to high-risk process mutations, preventing log volume exhaustion while capturing raw malicious shell launches.
* **`--debug-log=/var/log/gvisor/`**: Configures the host destination directory path where gVisor drops the matching `.boot` logs handled by our log tailer.

*Note: After modifying this file, you must restart your local Docker subsystem to apply the runtime parameters (`sudo systemctl restart docker`).*

## 3. Rule Actions & Parameter Reference

Every detection block under `[[rules]]` maps to a sequential `try_actions` list and a defensive `final_actions` fallback block.

### `validate_state`

* **Parameters:** None
* **System Action:** Validates that the container runtime still reports the context as actively running before invoking downstream mitigation modules.

### `pause` / `unpause` / `restart`

* **Parameters:** None
* **System Action:** Directly mutates the operational execution namespace of the target container ID.

### `log_json` / `log_critical`

* **Parameters:** None
* **System Action:** Forces an immediate, immutable audit payload entry out to the host standard output stream or journal.

### `commit_snapshot`

* **Parameters:** `prefix` (String)
* **System Action:** Commits the current volatile file layers of the container into an isolated local image registry tag matching: `<prefix>-<container_id>-<timestamp>`.

### `nft_blacklist`

* **Parameters:** `set_name` (String), `timeout` (String)
* **System Action:** Adds the container's resolved internal IP address directly into an active nftables set with an automatic kernel-level expiration drop window.

### `container_signal`

* **Parameters:** `signal` (String)
* **System Action:** Dispatches a native host-driven Linux signal override (e.g., `"SIGKILL"`, `"SIGSTOP"`) straight to the targeted task execution ring.

### `webhook_alert`

* **Parameters:** `url` (String)
* **System Action:** Dispatches an automated HTTP POST request via native OS `curl` to the specified endpoint (e.g., Slack, Teams, or an enterprise SIEM) containing a JSON payload detailing the targeted container ID.

### `run_custom_script`

* **Parameters:** `path` (String / File Path)
* **System Action:** Spawns a dedicated subprocess execution of an external binary file, automatically injecting runtime context as positional arguments: `$1` (Container ID), `$2` (Resolved Target IP), and `$3` (Raw Trigger Log Message). Executes within a 15-second bounded polling loop.

## 4. Sample Automation Script Template

When invoking `run_custom_script`, ensure the script begins with a standard shell definition and has its execute bit enabled (`chmod +x`).

```bash
#!/bin/bash
set -euo pipefail

# Capture the positional arguments emitted by the daemon loop
TARGET_CONTAINER_ID="${1}"
INTRUDER_IP="${2}"
RAW_LOG_TRIGGER="${3}"

echo "[EXT-HOOK] Active Incident response loop triggered for Context: ${TARGET_CONTAINER_ID}"
echo "[EXT-HOOK] Offending IP Address: ${INTRUDER_IP}"
echo "[EXT-HOOK] Raw Log Signature Match: ${RAW_LOG_TRIGGER}"

# Example Automation Action: Dump standard container logs to out-of-band space
docker logs "${TARGET_CONTAINER_ID}" > "/var/log/forensics/incident-${TARGET_CONTAINER_ID}.log" 2>&1
```

## 5. Host-Side nftables Policy Layouts

> ⚠️ **ARCHITECTURAL BOUNDARY WARNING**
> The `runsc-sentry-guard` daemon operates strictly as an **out-of-band set populator**. When an incident response pipeline triggers, the engine appends the container's internal bridge IP address directly into a named kernel set.
>
>
> The daemon **does not** create base tables, routing chains, or packet-filtering hooks on the host. Firewall policy enforcement is entirely delegated to the system supervisor. Implementing overly broad filtering postures risks inflicting an accidental self-inflicted Denial of Service (DoS) on legitimate, concurrent user sessions running within the same compromised namespace.
>
>

To prevent collateral damage, administrators must deploy surgical packet-filtering layouts on the host network edge. The following three blueprints use the daemon's default `inet security_ops` table and `container_blacklist` set references to achieve varying security profiles.

### ### Blueprint A: Total Isolation (Air-Gap Containment)

* **Use Case:** Maximum containment severity. Completely severs all inbound, outbound, and inter-container network connectivity for the compromised container instantly.

* **Impact:** High blast radius. Best suited for highly critical data-leak environments where active forensic preservation is preferred over application availability.

```text
table inet security_ops {
    set container_blacklist {
        type ipv4_addr
        flags timeout
    }

    chain forward {
        type filter hook forward priority filter; policy accept;

        # Drop ALL traffic to and from the quarantined container IP
        ip saddr @container_blacklist drop
        ip daddr @container_blacklist drop
    }
}
```

### ### Blueprint B: Outbound Suppression (Egress Quarantine)

* **Use Case:** Neutralizes reverse shells, out-of-band data exfiltration, and lateral internal network scanning.

* **Impact:** Controlled blast radius. Allows the container to continue receiving or responding to incoming ingress traffic normally, preserving external application uptime while stopping the compromise from spreading outward.

```text
table inet security_ops {
    set container_blacklist {
        type ipv4_addr
        flags timeout
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        
        # Block ONLY traffic originating FROM the container going OUT
        ip saddr @container_blacklist drop
    }
}
```

### ### Blueprint C: Connection-Tracking State Filtration (Zero-Collateral)

* **Use Case:** Highly recommended for dense, high-traffic production application nodes. Bypasses the "crossfire" dilemma entirely.

* **Impact:** Zero blast radius for valid users. Uses the Linux kernel connection tracking (`conntrack`) subsystem to permit already-established, legitimate user sessions (`established,related`) to complete their lifecycles seamlessly. Concurrently, it blocks the container from initializing **any** fresh outbound socket requests, trapping reverse shell dial-backs or malicious command-and-control (C2) setups instantly.

```text
table inet security_ops {
    set container_blacklist {
        type ipv4_addr
        flags timeout
    }

    chain forward {
        type filter hook forward priority filter; policy accept;

        # Allow active, pre-existing connections to complete safely
        ct state established,related accept

        # Drop any NEW connections initiated by the flagged container IP
        ip saddr @container_blacklist ct state new drop
    }
}
```

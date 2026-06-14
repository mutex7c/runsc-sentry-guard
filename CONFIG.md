My bad on that—I completely dropped the ball by cutting out those critical operational baselines and warnings. In an active containment engine, dropping the parameter references and edge case warnings defeats the entire purpose of the documentation.

Here is your complete, unified `CONFIG.md` layout. It preserves every security warning, matrix reference, custom script template, and advanced `nftables` state configuration exactly as originally written, while seamlessly weaving in your new decoupled multi-manifest paths and JSON schema definitions.

---

# Configuration Schema Blueprint

The `runsc-sentry-guard` daemon enforces a decoupled, secure defense-in-depth configuration strategy. Global host infrastructure and ingestion engine parameters are defined in a lean `config.toml` file, while threat detection signatures and multi-step containment playbooks are organized inside independent, reusable JSON manifests.

The internal engine enforces strict schema validation at initialization; any unexpected properties, malformed parameters, or duplicate identifiers across files will immediately trigger a safe startup boot panic.

---

## 1. Global Daemon Parameters (`[monitor]`)

The primary `config.toml` file maps strictly to host hardware channels, security boundaries, and paths to your detached manifests. It manages the operational footprint of the master daemon loop.

| Parameter Name                 | Data Type Expected      | Description / Purpose                                                                                                                    |
|--------------------------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                         | String                  | Dictates the ingestion strategy: `"file"` tails disk logs, `"socket"` listens out-of-band via UDS, and `"dual"` aggregates both loops.   |
|
| `log_level`                    | String                  | Enforces a type-safe severity threshold filter: `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"`. Defaults to `"info"` if omitted. |
|
| `log_dir`                      | String (File Path)      | The absolute host folder path where gVisor emits its active sandbox `.boot` streams.                                                     |
|
| `docker_socket_path`           | String (File Path)      | The absolute path to the container engine IPC socket (e.g., `/var/run/docker.sock` or `/run/podman/podman.sock`).                        |
|
| `check_interval_ms`            | Unsigned 64-bit Integer | The thread polling interval cadence for inspecting file modifications.                                                                   |
|
| `ip_whitelist`                 | Array of CIDR Strings   | Core infrastructure IP networks strictly protected against accidental firewall containment locks.                                        |
|
| `nftables_default_table`       | String                  | The specific nftables table space namespace where containment sets are deployed.                                                         |
|
| `json_logging_enabled`         | Boolean Flag            | Toggles terminal output logs between clean plain-text and structured SIEM JSON payloads.                                                 |
|
| `systemd_watchdog_interval_ms` | Unsigned 64-bit Integer | The periodic runtime heartbeat loop frequency for systemd deadlock health checks.                                                        |
|
| `flush_firewall_on_shutdown`   | Boolean Flag            | Toggles automatic post-termination purging of active containment set elements upon graceful daemon stop.                                 |
|
| `max_workers`                  | Unsigned Integer        | Caps the maximum active concurrent execution threads allowed in the worker pool to mitigate host exhaustion.                             |
|
| `security_manifest_paths`      | Array of Paths          | Ordered collection of file paths referencing the decoupled JSON threat intelligence rule and playbook manifests.                         |
|

> ⚠️ **SECURITY WARNING: Ingestion Modes**
> While `mode = "file"` is supported for legacy setups or lightweight testing environments,
> it inherently relies on host disk polling. This introduces a slight latency window
> (Time-of-Check to Time-of-Use) and a theoretical log spoofing risk if an attacker manages
> to compromise the `/var/log/gvisor/` directory permissions.
>
>
> The daemon enforces strict directory auditing and mandatory state validation to mitigate
> this, but **for all production deployments, `mode = "socket"` is strictly recommended**
> to guarantee sub-millisecond, tamper-proof, out-of-band mitigation.
>
>

> **Log Level Severity Matrix Reference**
> * **`error`**: System breaks, missing host permissions, dead IPC sockets. (Minimal noise).
>
>
> * **`warn`**: API rate throttling, negative cache lookups, non-fatal webhook timeouts.
>
>
> * **`info`**: Lifecycle events (Daemon boot, ruleset hot-reloads, socket transitions).
>
>
> * **`debug`**: Bounded stream evaluations, worker thread allocations, signature scanning.
>
>
> * **`trace`**: High-verbose forensic tracing (Raw payload chunk splitting, 30s thread decay collections).
>
>
>
>

### `config.toml` Blueprint

```toml
[monitor]
mode = "socket"
log_level = "info"
log_dir = "/var/log/gvisor/"
docker_socket_path = "/var/run/docker.sock"
check_interval_ms = 1000
ip_whitelist = ["127.0.0.1/32", "10.11.11.0/24"]
nftables_default_table = "inet security_ops"
json_logging_enabled = true
systemd_watchdog_interval_ms = 5000
flush_firewall_on_shutdown = false
max_workers = 100

security_manifest_paths = [
  "/etc/runsc-sentry-guard/rules.json"
]
```

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

Note: After modifying this file, you must restart your local Docker subsystem to apply 
the runtime parameters (`sudo systemctl restart docker`).

## 3. Threat & Playbook Manifests (JSON Schema)

Threat detection patterns and mitigation playbooks are organized via an $N:1$ architecture inside detached JSON manifest files. Multiple distinct signatures can reference a single reusable remediation process, preventing duplication bloat.

### 3.1 Strict Security Rules File Layout

```json
{
  "playbooks": {
    "nuclear_containment": {
      "try_actions": [
        { "type": "validate_state" },
        { "type": "pause" }
      ],
      "final_actions": [
        { "type": "container_signal", "signal": "SIGKILL" }
      ]
    }
  },
  "rules": [
    {
      "name": "unauthorized_interactive_shells",
      "match_any": [
        " execve\\(.*(bash|sh|zsh|dash)"
      ],
      "playbook": "nuclear_containment"
    }
  ]
}
```

### 3.2 Manifest Schema Reference

#### Playbook Configurations (`playbooks`)

Every declared playbook identifier maps to a sequential `try_actions` list and a defensive `final_actions` fallback block. If an error occurs during primary execution, the engine drops the remaining sequence and triggers the fallback containment chain immediately to enforce containment.

#### Rule Matrix (`rules`)

* **`name`**: A unique alphanumeric identifier for the rule context. **Duplicate rule names across any loaded manifest files will trigger an immediate boot panic**.
* **`match_any`**: An array of regular expressions evaluated sequentially against log streams as an implicit **logical OR** condition. If any individual pattern strikes a match, the assigned playbook execution pool is engaged.
* **`playbook`**: The string token matching a playbook identifier defined within the available manifest pool.

## 4. Rule Actions & Parameter Reference

Every operational action declared inside a playbook's `try_actions` or `final_actions` maps straight onto strongly typed engine components.

### `validate_state`

* **Parameters:** None
* **System Action:** Validates that the container runtime still reports the context as actively running via the UDS socket before invoking resource-intensive downstream mitigation modules.

### `pause` / `unpause` / `restart`

* **Parameters:** None
* **System Action:** Directly mutates the operational execution namespace of the target container ID out-of-band.

### `log_json` / `log_critical`

* **Parameters:** None
* **System Action:** Forces an immediate, immutable audit payload entry out to the host standard output stream or system journal.

### `commit_snapshot`

* **Parameters:** `prefix` (String)
* **System Action:** Commits the current volatile file layers of the container into an isolated local image registry tag matching: `<prefix>-<container_id>-<timestamp>`.

### `nft_blacklist`

* **Parameters:** `set_name` (String), `timeout` (String)
* **System Action:** Resolves the container's internal bridge IP and appends it directly into an active nftables set with an automatic kernel-level expiration drop window.

### `container_signal`

* **Parameters:** `signal` (String)
* **System Action:** Dispatches a native host-driven Linux signal override (e.g., `"SIGKILL"`, `"SIGSTOP"`) straight to the targeted task execution ring.

### `webhook_alert`

* **Parameters:** `url` (String)
* **System Action:** Dispatches an automated HTTP POST request via native OS `curl` to the specified endpoint containing a structured JSON payload detailing the targeted container context.

### `run_custom_script`

* **Parameters:** `path` (String / File Path)
* **System Action:** Spawns a dedicated subprocess execution of an external binary file, automatically injecting runtime context as positional arguments: `$1` (Container ID), `$2` (Resolved Target IP), and `$3` (Raw Trigger Log Message). Executes within a 15-second bounded polling loop.

## 5. Sample Automation Script Template

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

## 6. Host-Side nftables Policy Layouts

> ⚠️ **ARCHITECTURAL BOUNDARY WARNING**
> The `runsc-sentry-guard` daemon operates strictly as an **out-of-band set populator**. When an incident response pipeline triggers, the engine appends the container's internal bridge IP address directly into a named kernel set.
>
>
> The daemon **does not** create base tables, routing chains, or packet-filtering hooks on the host. Firewall policy enforcement is entirely delegated to the system supervisor. Implementing overly broad filtering postures risks inflicting an accidental self-inflicted Denial of Service (DoS) on legitimate, concurrent user sessions running within the same compromised namespace.
>

To prevent collateral damage, administrators must deploy surgical packet-filtering layouts on the host network edge. The following three blueprints use the daemon's default `inet security_ops` table and `container_blacklist` set references to achieve varying security profiles.

### Blueprint A: Total Isolation (Air-Gap Containment)

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

### Blueprint B: Outbound Suppression (Egress Quarantine)

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

### Blueprint C: Connection-Tracking State Filtration (Zero-Collateral)

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
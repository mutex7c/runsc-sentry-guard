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
| `seccomp_enabled`              | Boolean Flag                               | Enables the in-process Linux seccomp-bpf syscall filter after startup validation and capability trimming. Defaults to `true` on x86_64 Linux builds and `false` on unsupported build targets when omitted. |
| `systemd_watchdog_interval_ms` | Unsigned 64-bit Integer                    | The periodic runtime heartbeat loop frequency for systemd deadlock health checks.                                                               |

When `seccomp_enabled = true`, the daemon selects its syscall matrix from configured actions. Rules that only use native socket, file, webhook, and container-state operations run under the tighter core profile. Rules containing `nft_blacklist` or `run_custom_script` switch to the automation-compatible profile so inherited child processes such as `nft` or configured scripts can start without disabling seccomp entirely.

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
* **System Action:** Dispatches an automated HTTP(S) POST request via the in-process Rust client to the specified endpoint (e.g., Slack, Teams, or an enterprise SIEM) containing a JSON payload detailing the targeted container ID.

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

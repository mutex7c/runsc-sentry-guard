# Configuration Schema Blueprint

The `runsc-sentry-guard` daemon ingests a declarative TOML file layout. The internal engine enforces strict schema validation at initialization; any unexpected properties or malformed parameters will immediately cause a safe startup abort.

---

## 1. Global Daemon Parameters (`[monitor]`)

| Parameter Name                 | Data Type Expected                         | Description / Purpose                                                                                                                           |
|:-------------------------------|:-------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                         | String (`"file"`, `"socket"`, or `"dual"`) | Dictates the ingestion strategy. `file` tails disk logs, `socket` listens out-of-band via UDS, and `dual` aggregates both loops simultaneously. |
| `log_dir`                      | String (File Path)                         | The absolute host folder path where gVisor emits its active sandbox `.boot` streams.                                                            |
| `check_interval_ms`            | Unsigned 64-bit Integer                    | The thread polling interval cadence for inspecting file modifications.                                                                          |
| `ip_whitelist`                 | Array of CIDR Strings                      | Core infrastructure IP networks strictly protected against accidental firewall locks.                                                           |
| `nftables_default_table`       | String                                     | The specific nftables table space namespace where containment sets are deployed.                                                                |
| `json_logging_enabled`         | Boolean Flag                               | Toggles terminal output logs between clean plain-text and structured SIEM JSON payloads.                                                        |
| `systemd_watchdog_interval_ms` | Unsigned 64-bit Integer                    | The periodic runtime heartbeat loop frequency for systemd deadlock health checks.                                                               |

## 2. Container Runtime Engine Configuration (`daemon.json`)

For `runsc-sentry-guard` to receive high-fidelity system 
call telemetry out-of-band, you must configure Docker/Podman 
to instruct the runsc / gVisor supervisor to emit strace logs down to the host file system.

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

### `run_custom_script`
* **Parameters:** `path` (String / File Path)
* **System Action:** Spawns a dedicated subprocess execution of an external binary file, automatically injecting the targeted `container_id` string as the absolute first positional CLI argument (`$1`).

## 4. Sample Automation Script Template

When invoking `run_custom_script`, ensure the script begins with a standard shell definition and has its execute bit enabled (`chmod +x`).

```bash
#!/bin/bash
set -euo pipefail

# Capture the positional argument emitted by the daemon loop
TARGET_CONTAINER_ID="${1}"

echo "[EXT-HOOK] Active Incident response loop triggered for Context: ${TARGET_CONTAINER_ID}"

# Example Automation Action: Dump standard container logs to out-of-band space
docker logs "${TARGET_CONTAINER_ID}" > "/var/log/forensics/incident-${TARGET_CONTAINER_ID}.log" 2>&1

# Example Automation Action: Trigger notification events to a corporate SecOps web hook
curl -X POST -H 'Content-type: application/json' \
     --data "{\"text\":\"🚨 Runsc-Sentry-Guard dropped custom extension payload block onto container: ${TARGET_CONTAINER_ID}\"}" \
     https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

```
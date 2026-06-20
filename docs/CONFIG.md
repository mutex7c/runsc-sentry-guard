# CONFIGURATION

## 1. Global Daemon Parameters (`[monitor]`)

Global parameters are defined in `config.toml`, while threat detection
signatures and multi-step containment playbooks are organized in independent
JSON manifests.

| Parameter Name                 | Data Type Expected      | Description / Purpose                                                                                                                |
|--------------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                         | String                  | `"file"` tails disk logs (recommended for testing only), `"socket"` listens out-of-band via UDS, and `"dual"` aggregates both loops. |
|
| `log_level`                    | String                  | `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"`. Defaults to `"info"` if omitted.                                             |
|
| `log_dir`                      | String (File Path)      | Absolute host folder path to gVisor sandbox (`.boot`) streams.                                                                       |
|
| `docker_socket_path`           | String (File Path)      | Absolute path to the container engine IPC socket (e.g., `/var/run/docker.sock` or `/run/podman/podman.sock`).                        |
|
| `check_interval_ms`            | Unsigned 64-bit Integer | Thread polling interval for inspecting file modifications.                                                                           |
|
| `ip_whitelist`                 | Array of CIDR Strings   | IP networks whitelisted against accidental firewall containment locks.                                                               |
|
| `nftables_default_table`       | String                  | Specific nftables table space namespace where containment sets are deployed.                                                         |
|
| `json_logging_enabled`         | Boolean Flag            | Toggles output logs between plain-text and structured SIEM JSON payloads.                                                            |
|
| `systemd_watchdog_interval_ms` | Unsigned 64-bit Integer | Runtime heartbeat loop frequency for systemd deadlock health checks.                                                                 |
|
| `flush_firewall_on_shutdown`   | Boolean Flag            | Toggles automatic post-termination purging of active containment set elements upon graceful daemon stop.                             |
|
| `max_workers`                  | Unsigned Integer        | Caps the maximum active concurrent execution threads allowed in the worker pool to mitigate host exhaustion.                         |
|
| `security_manifest_paths`      | Array of Paths          | Collection of file paths referencing the JSON rule and playbook manifests.                                                           |
|

> **SECURITY WARNING: Ingestion Modes**
> While `mode = "file"` is supported for testing environments,
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

For `runsc-sentry-guard` to receive high-fidelity system call telemetry out-of-band, 
you must configure Docker/Podman to instruct the runsc / gVisor supervisor to emit 
strace logs to the host file system.

Append or merge the following configuration block into your 
global `/etc/docker/daemon.json` file:

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

Threat detection patterns and mitigation playbooks are organized 
via an $N:1$ architecture inside detached JSON manifest files. 

Multiple distinct signatures can reference a single reusable remediation 
process, preventing duplication bloat.

### 3.1 Rules File Layout

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

Every playbook identifier maps to a 
sequential `try_actions` list and a 
defensive `final_actions` fallback block. If an error 
occurs during primary execution, the engine drops the remaining sequence 
and triggers the fallback containment chain immediately to enforce containment.

#### Rule Matrix (`rules`)

* **`name`**: A unique alphanumeric identifier for the rule context. **Duplicate rule names across any loaded manifest files will trigger a boot panic**.
* **`match_any`**: An array of regular expressions evaluated against log streams as an implicit **logical OR** condition. If any individual pattern matches, the assigned playbook is executed.
* **`playbook`**: The string token matching a playbook identifier.

## 4. Rule Actions & Parameter Reference

Every operational action declared inside a playbook's 
`try_actions` or `final_actions` maps to specific engine commands.

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

> **ARCHITECTURAL BOUNDARY WARNING**
> 
> The `runsc-sentry-guard` daemon operates as an **out-of-band set populator**. 
> When an incident response pipeline triggers, the engine appends the container's 
> internal bridge IP address directly into a specified kernel set.
>
>
> The daemon **does not** create base tables, routing chains, 
> or packet-filtering hooks on the host. Firewall policy enforcement 
> is entirely delegated to the system administrator. 
> 
> Implementing overly 
> broad filtering can lead to accidental self-inflicted 
> Denial of Service (DoS) on legitimate, concurrent user sessions running 
> within the same compromised namespace.
>

To prevent collateral damage, administrators should deploy appropriate 
packet-filtering layouts on the host network edge. 

The following three 
blueprints use the daemon's default `inet security_ops` table 
and `container_blacklist` set references to achieve varying security profiles.

### Blueprint A: Total Isolation (Air-Gap Containment)

* **Use Case:** Maximum containment. Completely severs all inbound, outbound, and inter-container network connectivity for the compromised container instantly.
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
* **Impact:** Zero blast radius for valid users. Uses the Linux kernel connection tracking (`conntrack`) subsystem to permit already-established, legitimate user sessions (`established,related`) to complete their lifecycles seamlessly. Concurrently, it blocks the container from initializing **any** fresh outbound socket requests, trapping reverse shell dial-backs or malicious command-and-control (C2) setups.

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



---

# HOST SECURITY HARDENING & SANDBOXING

Because `runsc-sentry-guard` executes with elevated privileges, 
this document provides some blueprints required 
to restrict the daemon's host-level access to only the necessary directories 
and kernel interfaces while preserving the execution viability of custom 
administrative incident response playbooks.

Adjust to your individual environment as you see fit.

## 1. Systemd Sandboxing (Built-in Hardening)

The systemd service unit utilizes advanced Linux namespace isolation flags. 

This ensures that even if a vulnerability is discovered within our dependency tree, 
the binary cannot access unauthorized host directories, spawn arbitrary network 
listeners, or modify critical system configurations.

To ensure custom incident response playbooks have a safe space to write forensic 
artifacts without introducing a broad file-system attack surface, the profile 
defines a dedicated writable sandbox path under `/var/log/runsc-sentry-guard/`.

Ensure your system service file `/etc/systemd/system/runsc-sentry-guard.service` 
reflects these parameters:

```ini
[Unit]
Description=Runsc Sentry Guard Active Containment Daemon
After=docker.service
Requires=docker.service

[Service]
Type=notify
User=root
WorkingDirectory=/var/log/gvisor
ExecStart=/usr/sbin/runsc-sentry-guard /etc/runsc-sentry-guard/config.toml
Restart=always
RestartSec=3
WatchdogSec=10

# Security Hardening & Sandboxing Matrix
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
PrivateTmp=yes

# Hardened Data Path Channels
ReadWritePaths=/var/log/gvisor /var/run/ /var/log/runsc-sentry-guard/
```

## 2. AppArmor Security Profile

For systems running AppArmor (Ubuntu, Debian, openSUSE), 
deploy this profile to enforce Mandatory Access Controls (MAC). 

It restricts the daemon's file operations to the gVisor log directory 
and standard container IPC endpoints while creating strict execution 
gates for custom administrative playbooks.

> **CRITICAL SECURITY BOUNDARY:** To prevent arbitrary execution 
> vulnerabilities, all custom automation bash scripts must be stored 
> within the root-owned, locked-down folder path `/etc/runsc-sentry-guard/scripts/`. 
> The AppArmor profile permits system shell execution (`/bin/bash`) **exclusively** 
> when processing scripts inside this designated directory container.
>

Create `/etc/apparmor.d/usr.sbin.runsc-sentry-guard` using this blueprint:

```text
#include <tunables/global>

/usr/sbin/runsc-sentry-guard {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Allow standard logging outputs
  /usr/sbin/runsc-sentry-guard mr,
  
  # Strict directory access rules
  /var/log/gvisor/ r,
  /var/log/gvisor/** r,
  /var/log/runsc-sentry-guard/ rw,
  /var/log/runsc-sentry-guard/** rw,
  
  # Allow the daemon to read foreign process states for UDS resolution
  /proc/[0-9]*/cmdline r,
  /proc/[0-9]*/cgroup r,
  
  # Bounded container utility control gates
  /usr/sbin/nft rcx,
  
  # ─────────────────────────────────────────────────────────────────
  # SCRIPT EXTENSION GATES
  # ─────────────────────────────────────────────────────────────────
  # Allow the daemon to execute standard shells under environment inheritance (ix)
  /bin/sh ix,
  /bin/bash ix,
  /bin/dash ix,

  # Bound custom automation script execution strictly to our secure config tree
  /etc/runsc-sentry-guard/scripts/ r,
  /etc/runsc-sentry-guard/scripts/** rix,
  
  # Socket communication lines for container engines
  /var/run/docker.sock rw,
  /run/docker.sock rw,
  /run/podman/podman.sock rw,

  # Deny all other administrative or home access vectors explicitly
  deny /etc/** w,
  deny /home/** rw,
  deny /root/** rw,
}
```

Load and parse the updated ruleset into the active kernel:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.runsc-sentry-guard
```

## 3. Seccomp Architecture Note

Earlier alpha versions of this daemon utilized an 
internal `libseccomp` BPF filter natively. This was intentionally removed 
to support external mitigation playbooks (like spawning custom shell automations), 
which require broad, unpredictable system call matrices (DNS resolution, SSL loading, 
Netlink sockets, signal reaping).

Syscall sandboxing for the master process can be optionally extended 
via systemd `SystemCallFilter` fields. However, filters must be applied 
with caution if administrators design custom playbooks that require specialized 
debugging or system instrumentation tools.

## 4. Architectural Note: Execution Identity & DAC

Earlier alpha versions of this daemon attempted to perform an internal 
identity shift upon boot—dropping from `root` to an unprivileged 
user (`nobody`) while attempting to retain `CAP_NET_ADMIN` internally.

However, Linux Discretionary Access Control (DAC) requires 
standard `root` group ownership to interact with the container 
engine Unix Domain Socket (`/var/run/docker.sock`) and to reliably 
read privileged sandbox streams (`/var/log/gvisor/`). 

Attempting to strip DAC overrides fundamentally broke the daemon's 
core ingestion and state-validation mechanisms.

Consequently, internal identity manipulation has been explicitly removed. 
The daemon **must** execute as standard `root` (UID 0). All process bounding 
(restricting capabilities strictly to `CAP_NET_ADMIN`) and file-system 
jailing must be handled by the `systemd` supervisor or AppArmor profiles 
as defined above.
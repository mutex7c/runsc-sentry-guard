
# Technical Specification: runsc-sentry-guard (v1.0.0-Spec)

## 0. Motivation

While `runsc` (gVisor) provides exceptional kernel-level isolation for
containers, traditional container detection tools
often struggle or introduce unnecessary performance
overhead when trying to intercept deep sandbox system calls.

When a container running inside a runsc profile experiences an
exploit, it generates various Indicators Of Compromise (IOC)
inside the host-side debug streams. `runsc-sentry-guard` intercepts
these events out-of-band directly from the host edge.

It completely bypasses the need for complex
kernel-hooking architectures (like eBPF) or intrusive container
modifications, enabling real-time, zero-dependency
active containment.

## 0.1 Architectural Design Philosophy

`runsc-sentry-guard` challenges traditional container security conventions.
By shifting the defense boundary from inside the workload to the host edge, it fixes
the visibility and latency flaws inherent in legacy detection tools.

| Defensive Vector       | Traditional Agent Approaches                                                                                                                                                                                                                                                                                                                          | runsc-sentry-guard Architecture                                                                                                                                                                                                          |
|:-----------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Isolation Boundary** | **In-Workload Shims / Sidecars:** Run inside or attached to the container. If an attacker achieves container escape or root privilege, the security agent can be blinded, tampered with, or killed.                                                                                                                                                   | **Out-of-Band (Host Edge):** Operates completely decoupled at the host user-space layer. The sandboxed workload has zero visibility into the guard daemon, making it tamper-proof.                                                       |
| **Response Latency**   | **Passive Logging & Triage:** Collects events, streams them to a centralized SIEM, and waits for human security engineers to execute a script or manually isolate the infrastructure.                                                                                                                                                                 | **Active Automated Mitigation:** Bridges detection and containment into a single real-time loop. It mutates host firewalls and freezes task states the moment a signature is detected.                                                   |
| **Concurrency Scale**  | **Monolithic Event FIFO Queues:** Processes incoming logs sequentially. A single high-volume attack or a hanging mitigation script can block the entire event pipeline for adjacent workloads.                                                                                                                                                        | **Key-Based Serialization:** Spawns isolated, independent worker threads pinned to unique Container IDs. A complex containment routine on container A never stalls defenses for container B.                                             |
| **Ingestion Latency**  | **Disk Log Tailers:** Relies on gVisor writing `.boot` files to the host storage layer, introducing minor filesystem write overhead and potential TOCTOU (Time-of-Check to Time-of-Use) security latency. This option is supported by `runsc-sentry-guard` for testing, but UDS Stream Receiver / Socket Mode is strictly recommended for production. | **UDS Stream Receiver:** Bypasses host disk I/O completely. Runtimes stream telemetry straight into the daemon's user-space memory, dropping response latency to sub-millisecond intervals and eliminating disk-spoofing risks entirely. |

> **The Unix Philosophy: Do One Thing and Do It Well**
>
> Instead of attempting to be a bloated, monolithic "Swiss Army knife" agent that
> tries to handle everything from static vulnerability scanning to compliance auditing,
> `runsc-sentry-guard` focuses strictly on a single, clear objective: **ultra-low-latency,
> out-of-band threat containment for docker gVisor sandboxes**.
>
> We do not attempt to reinvent the wheel. The daemon purposefully delegates base firewall
> policy rulesets to `nftables`, background process management to `systemd`, and application
> isolation to `runsc`. By maintaining this functional focus, we keep
> a lean footprint, a minimized attack surface, and real-time containment speed.

## 1. System Constants & Execution Scope Defaults

To satisfy Filesystem Hierarchy Standards (FHS), maximize host isolation boundaries, 
and guarantee predictable resource profiles, the daemon enforces the following immutable 
architecture parameters:

### 1.1 Global Ingestion & Engine Metrics
* **Default Configuration Path:** `/etc/runsc-sentry-guard/config.toml`
* **Default gVisor Log Target Directory:** `/var/log/gvisor/`
* **Default Security Manifest Path:** `/etc/runsc-sentry-guard/rules.json`
* **Log File Match Extension:** The global directory crawler tracks files terminating strictly in `.boot` for out-of-band system call stream evaluation.
* **Internal State Tick Rate:** `1000ms` (The frequency threshold for running `getdents64` directory crawls to discover active sandbox assets).
* **Maximum In-Memory Log Buffer Line Ceiling:** `8192 bytes`. The ingestion stream engine processes chunks up to this maximum limit per line evaluation. Segments extending past this boundary without a newline delimiter are flagged as an anomaly, truncated, and skipped to protect host memory channels from buffer-bloat denial-of-service attacks.

### 1.1.a Out-of-Band Unix Domain Socket (UDS) Metrics
* **Default Socket Path:** `/var/run/runsc-sentry-guard.sock`
* **Access Control Mandatory Matrix:** Created socket paths are locked via `chmod 0660`, restricting streaming access explicitly to privileged root operations and authenticated container engine runtimes.
* **Ingestion Guard Limits:** Incoming data chunks are strictly processed up to a maximum limit of `8192 bytes` per line view. Any block surpassing this sequence boundary is dropped to prevent heap exploitation or denial-of-service attempts.

### 1.2 Concurrency & Core Safety Bounds
* **Worker Thread Inactivity Timeout:** `30,000ms` (30 seconds). If an independent key-serialized container worker thread processes all active incident payloads and remains idle with zero incoming channel messages for this duration, it automatically unregisters its mailbox from the global map, drops its channel receiver, and terminates safely to defend host RAM against long-term heap leaks.
* **Host Privilege Ceiling:** Host Privilege Ceiling (Delegated Sandboxing): The application executes natively as root (UID 0) to satisfy Discretionary Access Control (DAC) file permission requirements for host sockets and logging streams. Process containment and capability bounding (restricting the binary strictly to CAP_NET_ADMIN) is explicitly delegated to the host's process supervisor (systemd) rather than utilizing brittle, internal Linux capability mutations.
* **Mandatory File Open Flags:** On Unix deployment environments, file descriptor allocations are strictly bound to `O_NOFOLLOW` (safely aborting file access if the target path resolves to a symbolic link) and `O_CLOEXEC` (preventing descriptors from leaking into child execution rings).
* **Inode Credential Verification:** The daemon checks the metadata profile of every target file handle, dropping the parsing loop instantly if the file owner UID does not match `0` (root/docker daemon space), mitigating Time-of-Check to Time-of-Use (TOCTOU) file-swapping directory traversals.
* **Process Supervisor Notification Model:** Operates via systemd `Type=notify`. Lifecycle readiness hooks and periodic heartbeat pulses are dispatched via raw UnixDatagram socket packets explicitly addressed to the abstract host path defined in the `NOTIFY_SOCKET` environmental variable wrapper.

### 1.2.a Container Lifecycle Synchronization Gap (Known Limitation)
Because the active container ID whitelist cache updates on a polling cadence governed by `check_interval_ms`, there exists a temporary visibility micro-window (equal to the check interval duration) when a newly initialized container's ID is not yet present in the host daemon's memory.

Any telemetry alerts generated by a container during its absolute initialization phase—prior to the next cache refresh tick—will be dropped by the $O(1)$ input validation engine to defend against log-spoofing floods. To minimize this gap, production environments should reduce `check_interval_ms` to the lowest stable threshold or utilize out-of-band socket streaming exclusively.

## 2. Decoupled Manifest Schema Blueprint

The parsing engine relies on structural deserializers enforced 
via `#[serde(deny_unknown_fields)]`. If an unmapped or illegal property 
is discovered during initialization, the system drops back to a safe startup abort.

### 2.1 CONFIGURATION Structure (`config.toml`)
```toml
[monitor]
mode = "socket"
log_level = "debug"
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
  "/etc/runsc-sentry-guard/playbooks.json",
  "/etc/runsc-sentry-guard/rules.json"
]
```

### 2.2 RULE & PLAYBOOK JSON Structure (`rules.json`)

```json
{
  "playbooks": {
    "quarantine_and_kill": {
      "try_actions": [
        { "type": "validate_state" },
        { "type": "pause" },
        { "type": "nft_blacklist", "set_name": "container_blacklist", "timeout": "24h" }
      ],
      "final_actions": [
        { "type": "log_critical" },
        { "type": "container_signal", "signal": "SIGKILL" }
      ]
    }
  },
  "rules": [
    {
      "name": "unauthorized_interactive_shells",
      "match_any": [
        " execve\\(.*(bash|sh|zsh|dash)",
        " execve\\(.*(nc|ncat|socat)"
      ],
      "playbook": "quarantine_and_kill"
    }
  ]
}
```

*Note: The configuration schema supports `type = "kill"` as a functional runtime alias, mapping directly 
onto the internal `ContainerSignal` data structure via Serde token aliases.*

## 3. System Call Sandboxing Control

To support dynamic external mitigation playbooks (such as executing netlink hooks or 
spawning out-of-band notification subprocesses), in-application seccomp compilation 
has been deprecated. Process boundary restrictions and system call sandboxing are 
exclusively delegated to the host's process supervisor via systemd `SystemCallFilter` profiles.

### 3.1 Strict System Call Whitelist Matrix

| Syscall Functional Domain | Explicit Whitelisted Linux System Calls                                                                      | Technical Engine Purpose / Execution Context                                                                                                                |
|---------------------------|--------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Memory Protection**     | `brk`, `mmap`, `munmap`, `mprotect`, `madvise`                                                               | Required by the Rust allocator layer to manage stack setups and initialize page allocations safely.                                                         |
| **Secure File Handling**  | `openat`, `read`, `write`, `close`, `lseek`, `fstat`, `newfstatat`, `statx`, `pread64`, `pwrite64`           | Utilized by the file tailer loop to map directory file descriptors and parse bounded chunks of `.boot` streams.                                             |
| **Directory Traversals**  | `getdents64`                                                                                                 | Required by the master orchestrator directory crawler loop to scan for new log files.                                                                       |
| **Process Lifecycles**    | `clone`, `clone3`, `execve`, `wait4`, `exit`, `exit_group`, `futex`, `sched_yield`, `set_robust_list`        | Spawns isolated worker threads, enforces mutex synchronization, and invokes child containment commands.                                                     |
| **IPC Streams & Buffers** | `pipe`, `pipe2`, `fcntl`, `ioctl`, `writev`, `readv`                                                         | Handles asynchronous standard stream redirections and coordinates thread mailboxes securely.                                                                |
| **Asynchronous Timers**   | `epoll_create1`, `epoll_ctl`, `epoll_wait`, `nanosleep`, `clock_nanosleep`                                   | Used to tick checking delays and calculate the 30-second worker thread inactivity decay timeout window.                                                     |
| **System Signals**        | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigqueue`                                              | Allows the runtime engine to respond gracefully to process manager termination requests (`SIGTERM`).                                                        |
| **Network Frameworks**    | `socket`, `connect`, `bind`, `sendmsg`, `recvmsg`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `uname` | **Strict child-process boundaries:** Required to preserve the structural viability of downstream `curl`, `docker inspect`, and `nftables` netlink commands. |

## Appendix: High-Performance Unix Domain Socket (UDS) Server Spec

To achieve low-latency active threat containment without relying on host file logging disk writes, the daemon implements a parallel, memory-backed Unix Domain Socket listener subsystem.

### 1. Architectural Metrics & Endpoints
* **Socket File Descriptor Target Location:** `/var/run/runsc-sentry-guard.sock`
* **Access Control Mandatory Matrix:** Disposed path permissions are locked down via `chmod 0660` at initialization, restricting communication privileges exclusively to root applications and authenticated infrastructure runtime daemons (e.g., Docker/Podman engine wrappers).
* **Ingestion Guard Limits:** Incoming data packets read over individual socket streams undergo sequential line splits. Lines are bounded by a maximum threshold ceiling of `8192 bytes`. Any incoming block surpassing this sequence boundary is skipped immediately without parsing to isolate host memory resources against stream buffer overflow attacks.

### 2. Network Firewall Input Constraints
* **Timeout Verification Ruleset:** To eliminate malicious string interpolation patterns within downstream `nftables` commands, the containment engine validates all rule `timeout` parameters via an internal strict regular expression structure: `^\d+[smhd]$`.
* **Safe Startup Abort:** If an operational play parameter configuration (e.g., `timeout = "24h; drop table;"`) fails to pass this exact structural matrix check at deployment execution, the atomic action returns an error and directly triggers the emergency fallback mitigation playbook loop.

# System Requirements & Architecture Specification: runsc-sentry-guard

## 1. Executive Summary & Objective
`runsc-sentry-guard` is an ultra-lightweight, out-of-band Cloud-Native Detection and Response (CNDR)
daemon written in native Rust. Its primary objective is to monitor gVisor (`runsc`) sandbox debug
streams on a host system, identify runtime Indicators of Compromise (IOCs), and execute configurable,
atomized, fail-safe incident containment pipelines without introducing external runtime dependencies
or kernel-level hooking (e.g., eBPF) vulnerabilities.

## 2. Core Functional Requirements

### 2.1 Concurrency & Execution Model (Key-Based Isolation)
* **Parallel Dispatching:** The main log-tailing loop operates asynchronously, parsing log files line-by-line using tracked Inode descriptors. It acts strictly as an event router and never executes blocking incident response actions.
* **Per-Container Serialization:** To prevent race conditions and split-brain containment actions, execution payloads targeting the *same* Container ID are queued via bounded asynchronous channels (`std::sync::mpsc`) and executed sequentially inside a dedicated worker thread.
* **Multi-Container Parallelism:** Incidents occurring across *different* Container IDs are processed simultaneously in isolated worker threads to prevent thread starvation or global engine denial-of-service blockages.
* **Dual-Channel Routing:** The master log ingestion architecture scales into a parallel state. The asynchronously executed dispatch loop routes entries sourced simultaneously from tracked Inode descriptors (filesystem logs) and an out-of-band streaming Unix Domain Socket, operating without introducing blockages to the runtime engines.


### 2.2 Fault Tolerance & Self-Healing
* **Panic Isolation:** Runtime errors or execution panics inside an individual container worker thread are isolated via native thread boundaries. Thread containment failures will not disrupt the directory parsing loops or adjacent worker queues.
* **Fail-Safe Playbooks (`try/final` Architecture):** Every rule enforces a strict mitigation boundary. If any action inside the primary `try_actions` block returns an execution error, the engine instantly aborts the remaining chain and triggers the high-severity `final_actions` fallback block to force containment.

### 2.3 Input Validation & Safety Constraints
* **Cryptographic ID Validation:** Container IDs parsed from raw file streams must match a strict alphanumeric hex regex template (`[a-fA-F0-9]{12,64}`) before being routed down to the sub-execution worker engines.
* **Network Whitelisting:** Before mutating firewalls, target container IP profiles are matched against a declarative list of network CIDR scopes (`ip_whitelist`). The daemon is programmatically blocked from adding infrastructure addresses to host firewall drop sets.
* **Secure Subprocesses:** The application entirely avoids shell-spawning evaluation contexts (`sh -c`). All external systems (`docker`, `nft`) are invoked using native OS vectors via `Command::new`, passing arguments strictly as literal string slices.

## 3. Configuration Specification (`config.toml`)
The daemon ingests a declarative TOML configuration layout mapping directly to strongly typed, immutable data structures validated by Serde at initialization.

* **`[monitor]`**: Configures target gVisor observation directories, engine polling frequencies, core network whitelists, global firewall tables, and logging formats.
* **`[[rules]]`**: An array mapping text signatures to explicit operational mitigation strategies. Supported atomic actions are limited to:
    * `validate_state`: Verifies context status via the container engine socket before processing intensive tasks.
    * `pause` / `unpause` / `restart`: Mutates container run-states out-of-band.
    * `container_signal`: Dispatches explicit Linux kernel termination overrides (e.g., `"SIGKILL"`, `"SIGSTOP"`).
    * `nft_blacklist`: Intercepts container routing by pushing resolved IP addresses into auto-expiring firewall drop tables.
    * `run_custom_script`: Spawns external automation scripts, automatically injecting the targeted container ID as the first positional argument (`$1`).
    * `log_json` / `log_critical`: Directs structured audit telemetry entries out to system logging streams.

## 4. Cross-Platform Developer Environment Support
* **Target-OS Decoupling:** The codebase leverages conditional compilation attributes (`#[cfg(target_os = "linux")]`) to abstract infrastructure mutations.
* **Mock Execution Profile:** When executed on non-Linux platforms (such as macOS or Windows development workstations), the core firewall and system runtime layers automatically drop back to a simulation layer, printing mock actions to stdout instead of crashing.

## 5. Regulatory Compliance Mapping

### 5.1 Cyber Resilience Act (CRA) Alignment

| CRA Obligation             | `runsc-sentry-guard` Design Response                                                                                                                                                                                                                                                                                                                          |
|:---------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Security by Design**     | Built in native, memory-safe Rust. Eliminates standard buffer overflow, use-after-free, and command-injection vulnerabilities inherent in traditional C/C++ or Bash security tools.                                                                                                                                                                           |
| **Vulnerability Handling** | Out-of-band monitoring architecture. The guard runs entirely outside the sandbox context; a compromised container cannot manipulate the security logs or see the daemon watching it. The (optional) UDS configuration allows for completely diskless user-space operations, making log tampering practically impossible for a compromised container workload. |
| **Minimal Attack Surface** | Operates as a single compiled binary with zero external runtime package dependencies (no Python, Node, or shared interpreter layers required on the host).                                                                                                                                                                                                    |

### 5.2 NIS2 Directive Alignment (Supply Chain & Incident Response)

| NIS2 Requirement             | `runsc-sentry-guard` Design Response                                                                                                                                                       |
|:-----------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Incident Management**      | Moves beyond passive alerting. Provides automated, low-latency containment (freezing threats and isolating networks at the host edge) to satisfy proactive business continuity mandates.   |
| **Clean Logging & Auditing** | Emits standardized, structured JSON audit logs natively to the system journal, ensuring tamper-proof event records for corporate SIEM ingestion and post-incident reporting timelines.     |
| **Supply Chain Integrity**   | Compiled completely from audited source code via static linking. Features an ultra-lean dependency tree to radically reduce third-party package dependency risks for enterprise consumers. |

## 6. Deployment Architecture
* **Binary Standard Location:** `/usr/sbin/runsc-sentry-guard`
* **Configuration Space:** `/etc/runsc-sentry-guard/config.toml`
* **Execution Boundary:** Hardened systemd service restrictions utilizing `ProtectSystem=strict` to mount host configurations as entirely read-only, isolating capabilities exclusively to `CAP_NET_ADMIN`.

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

| CRA Obligation             | `runsc-sentry-guard` Design Response                                                                                                                                                 |
|:---------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Security by Design**     | Built in native, memory-safe Rust. Eliminates standard buffer overflow, use-after-free, and command-injection vulnerabilities inherent in traditional C/C++ or Bash security tools.  |
| **Vulnerability Handling** | Out-of-band monitoring architecture. The guard runs entirely outside the sandbox context; a compromised container cannot manipulate the security logs or see the daemon watching it. |
| **Minimal Attack Surface** | Operates as a single compiled binary with zero external runtime package dependencies (no Python, Node, or shared interpreter layers required on the host).                           |

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
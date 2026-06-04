# Detailed Technical Specification: runsc-sentry-guard (v1.0.0-Spec)

## 1. System Constants & Execution Scope Defaults

To satisfy Filesystem Hierarchy Standards (FHS), maximize host isolation boundaries, and guarantee predictable resource profiles, the daemon enforces the following immutable architecture parameters:

### 1.1 Global Ingestion & Engine Metrics
* **Default Configuration Path:** `/etc/runsc-sentry-guard/config.toml`
* **Default gVisor Log Target Directory:** `/var/log/gvisor/`
* **Log File Match Extension:** The global directory crawler tracks files terminating strictly in `.boot` for out-of-band system call stream evaluation.
* **Internal State Tick Rate:** `1000ms` (The frequency threshold for running `getdents64` directory crawls to discover active sandbox assets).
* **Maximum In-Memory Log Buffer Line Ceiling:** `8192 bytes`. The ingestion stream engine processes chunks up to this maximum limit per line evaluation. Segments extending past this boundary without a newline delimiter are flagged as an anomaly, truncated, and skipped to protect host memory channels from buffer-bloat denial-of-service attacks.

### 1.2 Concurrency & Core Safety Bounds
* **Worker Thread Inactivity Timeout:** `30,000ms` (30 seconds). If an independent key-serialized container worker thread processes all active incident payloads and remains idle with zero incoming channel messages for this duration, it automatically unregisters its mailbox from the global map, drops its channel receiver, and terminates safely to defend host RAM against long-term heap leaks.
* **Host Privilege Ceiling:** Ambient, permitted, and effective POSIX sets are stripped permanently down to strictly `CAP_NET_ADMIN` post-initialization. The engine completely drops full ambient root ownership before opening streaming files or processing untrusted inputs.
* **Mandatory File Open Flags:** On Unix deployment environments, file descriptor allocations are strictly bound to `O_NOFOLLOW` (safely aborting file access if the target path resolves to a symbolic link) and `O_CLOEXEC` (preventing descriptors from leaking into child execution rings).
* **Inode Credential Verification:** The daemon checks the metadata profile of every target file handle, dropping the parsing loop instantly if the file owner UID does not match `0` (root/docker daemon space), mitigating Time-of-Check to Time-of-Use (TOCTOU) file-swapping directory traversals.
* **Process Supervisor Notification Model:** Operates via systemd `Type=notify`. Lifecycle readiness hooks and periodic heartbeat pulses are dispatched via raw UnixDatagram socket packets explicitly addressed to the abstract host path defined in the `NOTIFY_SOCKET` environmental variable wrapper.

## 2. Configuration Schema Specification (`config.toml`)

The parsing engine uses a declarative, strict-typing deserializer enforced via `#[serde(deny_unknown_fields)]`. If an unmapped, malformed, or deprecated structural property is encountered during initialization, the daemon will gracefully abort boot routines and output a validation schema error.

### 2.1 Complete Schema Map Blueprint
```toml
[monitor]
log_dir = "/var/log/gvisor/"
check_interval_ms = 1000
ip_whitelist = ["127.0.0.1/32", "10.11.11.0/24", "192.168.3.0/24"]
nftables_default_table = "inet security_ops"
json_logging_enabled = true
systemd_watchdog_interval_ms = 5000

[[rules]]
name = "unauthorized_interactive_shells"
file_pattern = "*.boot"
regex_match = ' execve\(.*(bash|sh|zsh|dash|nc|ncat|socat)'

[[rules.try_actions]]
type = "validate_state"

[[rules.try_actions]]
type = "pause"

[[rules.try_actions]]
type = "commit_snapshot"
prefix = "forensic-snapshot"

[[rules.try_actions]]
type = "webhook_alert"
url = "[https://hooks.example.com/services/T0000/B0000/XXXX](https://hooks.example.com/services/T0000/B0000/XXXX)"

[[rules.try_actions]]
type = "nft_blacklist"
set_name = "container_blacklist"
timeout = "24h"

[[rules.try_actions]]
type = "restart"

[[rules.try_actions]]
type = "unpause"

[[rules.final_actions]]
type = "log_critical"

[[rules.final_actions]]
type = "kill"
signal = "SIGKILL"

[[rules.final_actions]]
type = "nft_blacklist"
set_name = "container_blacklist"
timeout = "168h"
```

*Note: The configuration schema supports `type = "kill"` as a functional runtime alias, mapping seamlessly onto the internal `ContainerSignal` data structure via Serde token aliases.*

## 3. Native In-Application Seccomp Sandbox Filter Blueprint

To enforce defense-in-depth security independent of external system configuration layers, the daemon’s main loop compiles a rigid Berkeley Packet Filter (BPF) system call whitelist directly into the active kernel ring immediately upon boot.

Any system call outside of this strict operational matrix will trigger an immediate `SIGSYS` kernel termination trap, locking down the daemon process if it experiences memory corruption or unauthorized code injection.

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


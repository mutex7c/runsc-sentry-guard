# Host Security Hardening & Sandboxing Guide

Because `runsc-sentry-guard` executes with elevated root 
privileges, this document provides baseline profiles 
required to restrict the daemon's host-level access to 
only the necessary directories and kernel interfaces.

## 1. Systemd Sandboxing (Built-in Hardening)

Our systemd service unit utilizes advanced Linux namespace isolation flags. This ensures that even if a vulnerability is discovered within our dependency tree, the binary cannot access user home directories, spawn arbitrary network listeners, or modify critical system binaries.

Ensure your service file contains these defensive parameters:

```ini
[Service]
ExecStart=/usr/sbin/runsc-sentry-guard
User=root

# File System Restrictions
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/gvisor /var/run/
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
PrivateTmp=yes

# Linux Kernel Capability Restrictions
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true

# System Call Filters (Built-in Seccomp engine)
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount
```

## 2. AppArmor Security Profile

For systems running AppArmor (Ubuntu, Debian, openSUSE), deploy this profile to enforce mandatory access controls (MAC). It explicitly restricts file operations to the gVisor log directory and the standard system socket environments.

Create `/etc/apparmor.d/usr.sbin.runsc-sentry-guard`:

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
  
  # Allow execution of Docker and Nftables control commands
  /usr/bin/docker rcx,
  /usr/sbin/nft rcx,
  
  # Socket communication lines for Docker communication
  /var/run/docker.sock rw,
  /run/docker.sock rw,

  # Deny all other administrative or home access vectors explicitly
  deny /home/** rw,
  deny /root/** rw,
}
```

Load the profile using: `sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.runsc-sentry-guard`

## 3. Strict Seccomp System Call Whitelist Reference

If you choose to use an explicit system-level seccomp enforcement tool (such as `minijail`, a custom libseccomp wrapper, or an outer container runtime configuration) to bind the binary, it must be restricted to the following whitelist.

Any system call outside of this strict operational matrix 
should result in an immediate `SIGSYS` kernel termination, 
blocking exploitation vectors like kernel privilege escalations.

### 3.1 Required System Calls Matrix

| Syscall Group          | Linux System Calls                               | Technical System Purpose                                                                                  |
|------------------------|--------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| **Basic Runtime**      | `brk`, `mmap`, `munmap`, `mprotect`              | Essential memory allocation and stack layout initialization for the Rust compiled binary.                 |
| **File I/O Stream**    | `openat`, `read`, `write`, `close`, `lseek`      | Used by the `tailer` module to poll, open, and read line-by-line streaming blocks from `.boot` files.     |
| **Directory Polling**  | `getdents64`, `newfstatat`, `statx`              | Used by the orchestrator loop to scan `/var/log/gvisor/` for the appearance of new sandbox files.         |
| **Subprocess Forking** | `clone`, `clone3`, `execve`, `wait4`             | Required to securely fork isolated worker threads and spawn child shells for the `docker` and `nft` CLIs. |
| **IPC & Piping**       | `pipe`, `pipe2`, `fcntl`                         | Handles internal cross-thread state routing and standard output capturing from spawned processes.         |
| **Concurrency Lock**   | `futex`, `sched_yield`                           | Utilized by the Rust standard library (`std::sync::Mutex` and channels) to orchestrate thread barriers.   |
| **Asynchronous I/O**   | `epoll_create1`, `epoll_ctl`, `epoll_wait`       | Required by background event loops and time delay managers (`thread::sleep`).                             |
| **Signal Handling**    | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn` | Allows the binary to gracefully register and respond to standard Linux termination triggers (`SIGTERM`).  |

### 3.2 Example Seccomp Filter Generation Script

To generate a raw BPF file or test these constraints using a standard `libseccomp` profile compiler, ensure your rule blueprint mirrors this logic layout:

```text
# Default Policy: Deny everything that isn't explicitly permitted
action KILL;

# Permitted execution profiles
allow {
    brk, mmap, munmap, mprotect,
    openat, read, write, close, lseek,
    getdents64, newfstatat, statx,
    clone, clone3, execve, wait4,
    pipe, pipe2, fcntl,
    futex, sched_yield,
    epoll_create1, epoll_ctl, epoll_wait,
    rt_sigaction, rt_sigprocmask, rt_sigreturn
}
```

# Host Security Hardening & Sandboxing Guide

Because `runsc-sentry-guard` executes with elevated root privileges, this document provides baseline profiles required to restrict the daemon's host-level access to only the necessary directories and kernel interfaces.

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
  /usr/bin/curl rcx,
  
  # Socket communication lines for Docker/Podman communication
  /var/run/docker.sock rw,
  /run/docker.sock rw,
  /run/podman/podman.sock rw,

  # Deny all other administrative or home access vectors explicitly
  deny /home/** rw,
  deny /root/** rw,
}
```

Load the profile using: `sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.runsc-sentry-guard`

## 3. Strict Seccomp System Call Whitelist Reference

If you choose to use an explicit system-level seccomp enforcement 
tool (such as `minijail`, a custom libseccomp wrapper, or an outer 
container runtime configuration) to bind the binary, it must be 
restricted to the following whitelist. This matrix perfectly matches 
the daemon's internal BPF compiler.

Any system call outside of this strict operational matrix will result 
in an immediate `SIGSYS` kernel termination, blocking exploitation 
vectors like kernel privilege escalations.

### 3.1 Required System Calls Matrix

| Syscall Group          | Linux System Calls                                                                                           | Technical System Purpose                                                                                 |
|------------------------|--------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| **Memory Protection**  | `brk`, `mmap`, `munmap`, `mprotect`, `madvise`                                                               | Essential memory allocation and stack layout initialization for the Rust compiled binary.                |
| **File I/O Stream**    | `openat`, `read`, `write`, `close`, `lseek`, `fstat`, `newfstatat`, `statx`, `pread64`, `pwrite64`           | Used by the `tailer` module to poll, open, and read line-by-line streaming blocks from `.boot` files.    |
| **Directory Polling**  | `getdents64`                                                                                                 | Used by the orchestrator loop to scan `/var/log/gvisor/` for the appearance of new sandbox files.        |
| **Process Lifecycles** | `clone`, `clone3`, `execve`, `wait4`, `exit`, `exit_group`, `futex`, `sched_yield`, `set_robust_list`        | Spawns isolated worker threads, enforces mutex synchronization, and invokes child containment commands.  |
| **IPC & Buffers**      | `pipe`, `pipe2`, `fcntl`, `ioctl`, `writev`, `readv`                                                         | Handles internal cross-thread state routing and standard output capturing from spawned processes.        |
| **Timers & Async**     | `epoll_create1`, `epoll_ctl`, `epoll_wait`, `nanosleep`, `clock_nanosleep`                                   | Tick checking delays and 30-second worker thread inactivity decay timeout windows.                       |
| **Signal Handling**    | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigqueue`                                              | Allows the binary to gracefully register and respond to standard Linux termination triggers (`SIGTERM`). |
| **Networking & HTTP**  | `socket`, `connect`, `bind`, `sendmsg`, `recvmsg`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `uname` | Native UDS container engine socket connections and curl Webhook dispatching.                             |
| **Privilege Drops**    | `prctl`                                                                                                      | Drops ambient capabilities but retain root for DAC purposes.                                             |

### 3.2 Example Seccomp Filter Generation Script

To generate a raw BPF file or test these constraints using a standard `libseccomp` profile compiler, ensure your rule blueprint mirrors this logic layout:

```text
# Default Policy: Deny everything that isn't explicitly permitted
action KILL;

# Permitted execution profiles
allow {
    brk, mmap, munmap, mprotect, madvise,
    openat, read, write, close, lseek, fstat, newfstatat, statx, pread64, pwrite64,
    getdents64,
    clone, clone3, execve, wait4, exit, exit_group, futex, sched_yield, set_robust_list,
    pipe, pipe2, fcntl, ioctl, writev, readv,
    epoll_create1, epoll_ctl, epoll_wait, nanosleep, clock_nanosleep,
    rt_sigaction, rt_sigprocmask, rt_sigreturn, rt_sigqueue,
    socket, connect, bind, sendmsg, recvmsg, sendto, recvfrom, setsockopt, getsockopt, uname,
    prctl, setresgid, setresuid
}
```
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

# Supervisor System Call Filters
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @module @raw-io @reboot @swap
```

Avoid a blanket `SystemCallFilter=~@privileged` rule for this daemon. That group includes `capset`, which is required during early startup while the process trims itself down to `CAP_NET_ADMIN`; the internal seccomp-bpf filter is installed immediately after that step.

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
  
  # Allow optional host control helpers used by response playbooks
  /usr/bin/docker rcx,
  /usr/sbin/nft rcx,

  # Outbound TCP for native webhook_alert HTTP(S) delivery
  network inet stream,
  network inet6 stream,
  
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

## 3. Internal Seccomp-BPF Architecture

The daemon now installs an in-process Linux seccomp-bpf filter by default on x86_64 Linux builds via `seccomp_enabled = true`. The filter is loaded after configuration validation and capability trimming, before monitor threads or worker threads are created, so all later daemon threads inherit the same kernel boundary. Unsupported architectures default to `seccomp_enabled = false`; explicitly enabling seccomp there fails closed during startup until an architecture-specific syscall table is added.

Two profiles are selected automatically from the configured rule actions:

| Profile | When Used | Notes |
|---------|-----------|-------|
| `core` | Rules do not spawn external response tools. | Omits `execve` and process wait syscalls while allowing file/UDS ingestion, Docker Engine UDS requests, timers, logging, and worker synchronization. |
| `automation-compatible` | Any rule uses `nft_blacklist` or `run_custom_script`. | Keeps seccomp enabled while allowing the broader syscall matrix needed by inherited `nft` or configured script processes. |

Systemd `SystemCallFilter` remains a recommended outer supervisor layer, especially for native systemd deployments. The internal filter covers non-systemd environments such as minimal Docker or Alpine-style hosts where only the daemon binary and kernel seccomp support are available.

To disable the internal filter for emergency compatibility testing, set `seccomp_enabled = false` in `[monitor]`. Production deployments should leave it enabled and adjust response playbooks rather than relying on a disabled syscall boundary.

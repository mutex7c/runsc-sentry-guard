
# Host Security Hardening & Sandboxing Guide

Because `runsc-sentry-guard` executes with elevated privileges, this document provides the production-validated blueprints required to restrict the daemon's host-level access to only the necessary directories and kernel interfaces while preserving the execution viability of custom administrative incident response playbooks.

## 1. Systemd Sandboxing (Built-in Hardening)

The systemd service unit utilizes advanced Linux namespace isolation flags. This ensures that even if a vulnerability is discovered within our dependency tree, the binary cannot access unauthorized host directories, spawn arbitrary network listeners, or modify critical system configurations.

To ensure custom incident response playbooks have a safe space to write forensic artifacts without introducing a broad file-system attack surface, the profile defines a dedicated writable sandbox path under `/var/log/runsc-sentry-guard/`.

Ensure your system service file `/etc/systemd/system/runsc-sentry-guard.service` reflects these exact parameters:

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

For systems running AppArmor (Ubuntu, Debian, openSUSE), deploy this profile to enforce Mandatory Access Controls (MAC). It restricts the daemon's file operations to the gVisor log directory and standard container IPC endpoints while creating strict execution gates for custom administrative playbooks.

> ⚠️ **CRITICAL SECURITY BOUNDARY:** To prevent arbitrary execution vulnerabilities, all custom automation bash scripts must be stored strictly within the root-owned, locked-down folder path `/etc/runsc-sentry-guard/scripts/`. The AppArmor profile permits system shell execution (`/bin/bash`) **exclusively** when processing scripts inside this designated directory container.
>
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

Earlier alpha versions of this daemon attempted to compile an internal `libseccomp` BPF filter natively. This was removed to support external mitigation playbooks (like spawning custom shell automations), which require broad, unpredictable system call matrices (DNS resolution, SSL loading, Netlink sockets, signal reaping).

Syscall sandboxing for the master process can be optionally extended via systemd `SystemCallFilter` fields. However, filters must be applied with caution if administrators design custom playbooks that require specialized debugging or system instrumentation tools.

## 4. Architectural Note: Execution Identity & DAC

Earlier alpha versions of this daemon attempted to perform an internal identity shift upon boot—dropping from `root` to an unprivileged user (`nobody`) while attempting to retain `CAP_NET_ADMIN` internally.

However, Linux Discretionary Access Control (DAC) requires standard `root` group ownership to interact with the container engine Unix Domain Socket (`/var/run/docker.sock`) and to reliably read privileged sandbox streams (`/var/log/gvisor/`). Attempting to strip DAC overrides fundamentally broke the daemon's core ingestion and state-validation mechanisms.

Consequently, internal identity manipulation has been explicitly removed. The daemon **must** execute as standard `root` (UID 0). All process bounding (restricting capabilities strictly to `CAP_NET_ADMIN`) and file-system jailing must be handled by the `systemd` supervisor or AppArmor profiles as defined above.
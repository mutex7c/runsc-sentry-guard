# Host Security Hardening & Sandboxing Guide

Because `runsc-sentry-guard` executes with elevated root privileges, this document provides baseline profiles required to restrict the daemon's host-level access to only the necessary directories and kernel interfaces.

## 1. Systemd Sandboxing (Built-in Hardening)

Our systemd service unit utilizes advanced Linux namespace isolation flags. This ensures that even if a vulnerability is discovered within our dependency tree, the binary cannot access user home directories, spawn arbitrary network listeners, or modify critical system binaries.

Ensure your service file contains these defensive parameters:

```ini
[Service]
Type=notify
User=root
WorkingDirectory=/var/log/gvisor
ExecStart=$BIN_DEST
Restart=always
RestartSec=3
WatchdogSec=10

# Security Hardening & Sandboxing Matrix
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/gvisor /var/run/
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
PrivateTmp=yes
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
  
  # Allow the daemon to read foreign process command lines
  # This lets the UDS track securely resolve true container identities
  /proc/[0-9]*/cmdline r,
  
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

## 3. Seccomp Architecture Note

Earlier alpha versions of this daemon attempted to compile an internal `libseccomp` BPF 
filter natively. This was removed to support external mitigation playbooks 
(like spawning `curl` and `nft`), which require broad, unpredictable system 
call matrices (DNS resolution, SSL loading, Netlink sockets).

Syscall sandboxing is now exclusively delegated to the Systemd `SystemCallFilter` profiles 
defined in the provided service unit.

## 4. Architectural Note: Execution Identity & DAC

Earlier alpha versions of this daemon attempted to perform an internal identity shift 
upon boot—dropping from `root` to an unprivileged user (`nobody`) while attempting 
to retain `CAP_NET_ADMIN` internally. 

However, Linux Discretionary Access Control (DAC) requires standard `root` group 
ownership to interact with the container engine Unix Domain Socket (`/var/run/docker.sock`) 
and to reliably read privileged sandbox streams (`/var/log/gvisor/`). Attempting to strip DAC overrides fundamentally broke the daemon's core ingestion and state-validation mechanisms. 

Consequently, internal capability manipulation has been explicitly removed. The 
daemon **must** execute as standard `root` (UID 0). All capability bounding 
(restricting the process strictly to `CAP_NET_ADMIN`) and file-system jailing 
must be delegated to the `systemd` supervisor or AppArmor profiles as defined above.
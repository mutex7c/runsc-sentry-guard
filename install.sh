#!/bin/sh
set -e

# Establish FHS-compliant deployment destination paths
BIN_DEST="/usr/sbin/runsc-sentry-guard"
CONF_DIR="/etc/runsc-sentry-guard"
CONF_DEST="$CONF_DIR/config.toml"
RULES_DEST="$CONF_DIR/rules.json"
SERVICE_DEST="/etc/systemd/system/runsc-sentry-guard.service"

# Enforcement Boundary: Enforce administrative privileges check
if [ "$(id -u)" -ne 0 ]; then
    echo "Installation Error: This deployment routine must be run with root permissions (sudo)." >&2
    exit 1
fi

echo "Bootstrapping runsc-sentry-guard installation pipeline..."

# Locate build artifact from native cargo, containerized cargo, or turnkey download path
if [ -f "./target/release/runsc-sentry-guard" ]; then
    echo "Verified local release build target artifact. Deploying..."
    cp "./target/release/runsc-sentry-guard" "$BIN_DEST"
elif [ -f "./runsc-sentry-guard" ]; then
    echo "Verified turnkey/pre-compiled binary in current directory. Deploying..."[cite: 1]
    cp "./runsc-sentry-guard" "$BIN_DEST"[cite: 1]
else
    echo "Execution Error: Compiled binary artifact not found at './target/release/runsc-sentry-guard' or './runsc-sentry-guard'." >&2[cite: 1]
    echo "Please compile the application via 'cargo build --release' or download a release binary before deploying." >&2[cite: 1]
    exit 1
fi

# Restrict file execution permissions on binary
chmod 700 "$BIN_DEST"
chown root:root "$BIN_DEST"

# Provision configuration file paths securely
if [ ! -d "$CONF_DIR" ]; then
    mkdir -p "$CONF_DIR"
    chmod 750 "$CONF_DIR"
fi

# Create a dedicated, secure subdirectory for custom admin scripts
if [ ! -d "$CONF_DIR/scripts" ]; then
    mkdir -p "$CONF_DIR/scripts"
    chmod 750 "$CONF_DIR/scripts"
fi

# Create a dedicated, authorized mutable path for script forensic outputs
if [ ! -d "/var/log/runsc-sentry-guard" ]; then
    mkdir -p "/var/log/runsc-sentry-guard"
    chmod 750 "/var/log/runsc-sentry-guard"
fi

# Deploy centralized environment config profile[cite: 1]
if [ ! -f "$CONF_DEST" ]; then
    if [ -f "./config.toml" ]; then
        echo "Found personalized config.toml file. Deploying to production folder..."
        cp "./config.toml" "$CONF_DEST"
    else
        echo "No active configuration found. Deploying system defaults via configuration template..."
        cp "./config.toml.example" "$CONF_DEST"
    fi
    chmod 640 "$CONF_DEST"
else
    echo "Active profile detected at $CONF_DEST. Skipping file overwrite rules."
fi

# Deploy decoupled decoupled rules manifest profile
if [ ! -f "$RULES_DEST" ]; then
    if [ -f "./rules.json" ]; then
        echo "Found personalized rules.json file. Deploying to production folder..."
        cp "./rules.json" "$RULES_DEST"
    else
        echo "No active rules manifest found. Deploying system defaults via configuration template..."
        cp "./rules.json.example" "$RULES_DEST"
    fi
    chmod 640 "$RULES_DEST"
else
    echo "Active rules manifest detected at $RULES_DEST. Skipping file overwrite rules."
fi

# Ensure correct root ownership across the entire configuration directory container
chown -R root:root "$CONF_DIR"

# Provision host systemd service structures if native paths are present
if [ -d "/run/systemd/system" ]; then
    echo "Systemd supervisor layers detected. Generating hardened daemon unit configuration..."
    cat << EOF > "$SERVICE_DEST"
[Unit]
Description=Runsc Sentry Guard Active Containment Daemon
After=docker.service
Requires=docker.service

[Service]
Type=notify
User=root
WorkingDirectory=/var/log/gvisor
ExecStart=$BIN_DEST
Restart=always
RestartSec=3
WatchdogSec=10

# Security Hardening & Sandboxing Matrix (PRESERVED)
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
PrivateTmp=yes

# SURGICAL AMENDMENT: Added authorized output directory for incident forensics
ReadWritePaths=/var/log/gvisor /var/run/ /var/log/runsc-sentry-guard/

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SERVICE_DEST"

    # Force systemd subsystem index synchronization updates
    systemctl daemon-reload

    echo "Systemd service profile armed. To activate run: sudo systemctl enable --now runsc-sentry-guard"

else
    echo "Warning: Systemd initialized configuration space not located. Please establish process supervisor profiles manually."
fi

# ==============================================================================
# Mandatory Access Control (MAC) Provisioning: AppArmor
# ==============================================================================
if [ -f "/sys/module/apparmor/parameters/enabled" ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" = "Y" ]; then
    echo "AppArmor MAC detected on host kernel. Provisioning security profile..."
    AA_PROFILE="/etc/apparmor.d/usr.sbin.runsc-sentry-guard"

    cat << 'EOF' > "$AA_PROFILE"
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

  # Bound core utility execution limits
  /usr/bin/docker rcx,
  /usr/sbin/nft rcx,
  /usr/bin/curl rcx,

  # ─────────────────────────────────────────────────────────────────
  # SCRIPT EXTENSION GATES
  # ─────────────────────────────────────────────────────────────────
  # Allow the daemon to execute standard shells under inheritance (ix)
  /bin/sh ix,
  /bin/bash ix,
  /bin/dash ix,

  # Force custom automation scripts to reside strictly inside our root-owned,
  # locked-down configuration folder to prevent arbitrary execution vulnerabilities.
  /etc/runsc-sentry-guard/scripts/ r,
  /etc/runsc-sentry-guard/scripts/** rix,

  # Socket communication lines for Docker/Podman communication
  /var/run/docker.sock rw,
  /run/docker.sock rw,
  /run/podman/podman.sock rw,

  # Deny all other administrative or home access vectors explicitly
  deny /home/** rw,
  deny /root/** rw,
}
EOF

    chmod 644 "$AA_PROFILE"

    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -r "$AA_PROFILE"
        echo "AppArmor profile successfully compiled and loaded into the active kernel."
    else
        echo "Warning: apparmor_parser binary not found in PATH. Profile staged at $AA_PROFILE but not loaded."
    fi
else
    echo "AppArmor not active on this host kernel. Skipping MAC profile deployment."
fi

echo "Installation complete!"
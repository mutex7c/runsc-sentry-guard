# runsc-sentry-guard

An ultra-lightweight, out-of-band active incident response daemon 
for `runsc` (gVisor) sandboxes written in memory-safe Rust.

> ⚠️ **Development Status: ALPHA** 
> > This daemon has been structurally verified and 
> tested in development environments.
> 
> DO NOT USE in production environments yet!

## 1. Motivation

`runsc` (gVisor) provides exceptional kernel-level isolation for 
containers, but traditional container detection tools 
often struggle or introduce unnecessary performance 
overhead when trying to intercept deep sandbox system calls. 
When a container running inside a runsc profile undergoes an 
exploit, it generates high-fidelity indicators inside the 
host-side debug streams.

`runsc-sentry-guard` intercepts these events out-of-band directly 
from the host edge. It completely bypasses the need for complex 
kernel-hooking architectures (like eBPF) or intrusive container 
modifications, delivering immediate, zero-dependency 
active containment.

## 2. Architectural Design Philosophy

`runsc-sentry-guard` is built to challenge traditional container security conventions. By shifting the defense boundary from inside the workload to the host edge, it fixes the visibility and latency flaws inherent in legacy detection tools.

| Defensive Vector       | Traditional Agent Approaches                                                                                                                                                                                                                                                                                                  | runsc-sentry-guard Architecture                                                                                                                                                                                                          |
|:-----------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Isolation Boundary** | **In-Workload Shims / Sidecars:** Run inside or attached to the container. If an attacker achieves container escape or root privilege, the security agent can be blinded, tampered with, or killed.                                                                                                                           | **Out-of-Band (Host Edge):** Operates completely decoupled at the host user-space layer. The sandboxed workload has zero visibility into the guard daemon, making it tamper-proof.                                                       |
| **Response Latency**   | **Passive Logging & Triage:** Collects events, streams them to a centralized SIEM, and waits for human security engineers to write a script or manually isolate the infrastructure.                                                                                                                                           | **Active Automated Mitigation:** Bridges detection and containment into a single sub-second loop. It mutates host firewalls and freezes task states the moment a signature lands.                                                        |
| **Concurrency Scale**  | **Monolithic Event FIFO Queues:** Processes incoming logs sequentially. A single high-volume attack or a hanging mitigation script can block the entire event pipeline for adjacent workloads.                                                                                                                                | **Key-Based Serialization:** Spawns isolated, independent worker threads pinned to unique Container IDs. A complex containment routine on container A never stalls defenses for container B.                                             |
| **Ingestion Latency**  | **Disk Log Tailers:** Relies on gVisor writing `.boot` files to the host storage layer, introducing minor filesystem write overhead and potential TOCTOU (Time-of-Check to Time-of-Use) security latency. This option is supported for testing, but UDS Stream Receiver / Socket Mode is strictly recommended for production. | **UDS Stream Receiver:** Bypasses host disk I/O completely. Runtimes stream telemetry straight into the daemon's user-space memory, dropping response latency to sub-millisecond intervals and eliminating disk-spoofing risks entirely. |

## 3. Core Documentation & Context Links

* [Product Requirements & Compliance Specs (CRA & NIS2)](./REQUIREMENTS_AND_COMPLIANCE.md)
* [Deep Technical Implementation Specification](./TECHNICAL_SPECIFICATION.md)
* [Comprehensive Configuration & Script Specs](./CONFIG.md)
* [Host Hardening Profiles (AppArmor, Seccomp, Systemd)](./SECURITY_HARDENING.md)

## 4. Compilation & Assembly

Choose **one** of the following compilation workflows based on your host environment constraints:

### Path A: Local Rust Toolchain Execution (Developers)

If you have the stable Rust compiler toolchain installed natively on your local development machine, run:

```bash
cargo build --release
```

The optimized artifact will be output directly to `./target/release/runsc-sentry-guard`.

### Path B: Toolchain-Free Containerized Compilation (Production Servers)

If you do not want to install the Rust compiler natively on your production host machine, you can build the binary inside an ephemeral, official container wrapper:

```bash
docker run --rm -v "$PWD":/usr/src/guard -w /usr/src/guard rust:1.96-alpine cargo build --release
```

This command mounts your local source directories, leverages the isolated build container cache, 
and drops the compiled native Linux binary smoothly into your local `./target/release/` output 
path without polluting your host engine dependencies.

### Path C: Automated CI/CD Image Assembly (Cloud-Native)

To distribute and run the guard inside containerized or orchestrated environments (like Kubernetes), 
utilize this multi-stage `Dockerfile`. It compiles the binary within an isolated build layer and copies it into a highly stripped, minimal runtime image to keep the attack surface microscopic.

Create a file named `Dockerfile` in your root folder:

```dockerfile
# Stage 1: Build Environment
FROM rust:1.96-alpine AS builder
WORKDIR /usr/src/runsc-sentry-guard
COPY . .
RUN cargo build --release

# Stage 2: Minimal Production Image
FROM alpine:3.23
RUN apk add --no-cache nftables iptables docker-cli
COPY --from=builder /usr/src/runsc-sentry-guard/target/release/runsc-sentry-guard /usr/sbin/runsc-sentry-guard
ENTRYPOINT ["/usr/sbin/runsc-sentry-guard"]
```

## 5. Installation & Deployment

### 5.1 Prerequisites

* A Linux host system running a supported modern kernel distribution (Debian, Ubuntu, RHEL, Fedora, Arch).
* Docker or Podman running workloads utilizing the gVisor `runsc` runtime wrapper.
* `nftables` active on the host edge for automated network isolation support.
* If mode = "socket" or "dual" is selected, the deployment environment must allow socket allocation under /var/run/.

### 5.2 Step 1: Acquire the Source Code

Choose the method that matches your environment setup:

* **Option 1: Using Git (Standard Clone)**
  ```bash
  git clone https://github.com/mutex7c/runsc-sentry-guard.git
  cd runsc-sentry-guard
  ```

* **Option 2: Without Git (Tarball curl for minimal servers)**
  ```bash
  curl -L https://github.com/mutex7c/runsc-sentry-guard/tarball/main | tar -xz
  cd mutex7c-runsc-sentry-guard-*
  ```

### 5.3 Step 2: Establish Configuration Profile

Provision your example configuration file blueprint:

```bash
cp config.toml.example config.toml
```

Open and modify `config.toml` to customize your threat signatures, define core infrastructure whitelists, and align your mitigation playbooks.

### 5.4 Step 3: Run the System Installer

Ensure the installer script has administrative execution permissions on the host system:

```bash
chmod +x install.sh
```

Execute the automated installer shell script with root privileges to establish FHS directory structures, copy binaries to `/usr/sbin/`, and register the background engine:

```bash
sudo ./install.sh
```

Enable and boot the service container loop via systemd:

```bash
sudo systemctl enable --now runsc-sentry-guard
```

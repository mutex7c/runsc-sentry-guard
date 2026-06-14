## 1. Compilation & Assembly

Choose **one** of the following compilation workflows based on your host environment
constraints:

### Path A: Local Rust Toolchain Execution (Developers)

If you have the stable Rust compiler toolchain installed natively on your local
development machine, run:

```bash
cargo build --release
```

The optimized artifact will be output directly to `./target/release/runsc-sentry-guard`.

### Path B: Toolchain-Free Containerized Compilation (Production Servers)

If you do not want to install the Rust compiler natively on your production host machine,
you can build the binary inside an ephemeral, official container wrapper:

```bash
docker run --rm -v "$PWD":/usr/src/guard -w /usr/src/guard rust:1.96-alpine cargo build --release
```

This command mounts your local source directories, leverages the isolated build container cache,
and drops the compiled native Linux binary smoothly into your local `./target/release/` output
path without polluting your host engine dependencies.

### Path C: Automated CI/CD Image Assembly (Cloud-Native)

To distribute and run the guard inside containerized or orchestrated environments
(like Kubernetes), use this multi-stage `Dockerfile`. It compiles the binary within
an isolated build layer and copies it into a highly stripped, minimal runtime image
to keep the attack surface negligible.

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

## 2. Installation & Deployment

### 2.1 Prerequisites

* A Linux host system running a supported modern kernel distribution (Debian, Ubuntu, RHEL, Fedora, Arch).
* Docker or Podman running workloads utilizing the gVisor `runsc` runtime wrapper.
* `nftables` active on the host edge for automated network isolation support.
* If mode = "socket" or "dual" is selected, the deployment environment must allow socket allocation under /var/run/.

### 2.2 Step 1: Acquire the Source Code

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

### 2.3 Step 2: Establish Configuration Profile

Provision your centralized environment configuration and your threat rules manifest blueprints:

```bash
cp config.toml.example config.toml
cp rules.json.example rules.json
```

1. Open `config.toml` to declare your system environment baselines, network whitelists, and paths to your manifests.
2. Modify `rules.json` to manage reusable, automated active containment playbooks and group threat intelligence patterns seamlessly.

### 2.4 Step 3: Run the System Installer

Ensure the installer script has administrative execution permissions
on the host system:

```bash
chmod +x install.sh
```

Execute the automated installer shell script with root privileges
to establish FHS directory structures, copy binaries to `/usr/sbin/`, and register the background engine:

```bash
sudo ./install.sh
```

Enable and boot the service container loop via systemd:

```bash
sudo systemctl enable --now runsc-sentry-guard
```

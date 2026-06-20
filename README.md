# runsc-sentry-guard

An ultra-lightweight, out-of-band active incident response daemon 
for `runsc` (gVisor) sandboxes written in Rust.

> ⚠️ **Development Status: ALPHA** 
> 
> You are very welcome to test and contribute, but
> DO NOT USE in production environments yet!

## TL;DR

If your application is running inside a sandboxed gVisor container, it will likely 
prevent an adversary from easily taking over your entire server.

But it doesn't automatically stop them from making a mess *inside* the container 
if they find a loophole in your app or manage to deploy a zero-day exploit.

`runsc-sentry-guard` listens to the container's internal events 
from the host side (without requiring anything running inside the container).

The moment it detects indicators of compromise (like an unauthorized shell or binary execution),
it takes action:

*   Lock down and pauses the compromised container 
*   Isolate the Network to prevent data egress and payload loading
*   Take a forensic snapshot of the container's memory and file system 
*   Ring the Alarm via audit logs to your SIEM or direct webhooks

Traditional security tools sit *inside* the container alongside your app. 
If an automated payload gets root access, they can likely blind or turn off 
the security tool.

Because `runsc-sentry-guard` operates entirely **out-of-band** (from the 
outside host edge), the workload has zero visibility into the guard daemon.

Our goal is to provide enterprise-grade, real-time cyber response capabilities 
with **zero** performance impact on the running applications.

### Turnkey Quick Start (Run in 60 Seconds)

For rapid evaluations on staging instances, you can fetch the pre-compiled 
release artifacts directly.

> **Platform Compatibility Warning:** These turnkey commands and real-time 
> containment loops require a native Linux operating system. Running 
> this binary directly on a macOS terminal or Windows PowerShell prompt 
> will invoke testing / simulation mode (`[DEV-MOCK]`).
>

```bash
# 1. Download the latest stable release and config samples

curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/runsc-sentry-guard
curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/config.toml.example
curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/rules.json.example

# 2. Initialize your config (adjust as required)

mv config.toml.example config.toml
mv rules.json.example rules.json

# 3. Arm the executable and start out-of-band monitoring

chmod +x runsc-sentry-guard
sudo ./runsc-sentry-guard config.toml
```

## Documentation & Context Links

* [Source Compilation & System Installation Guide](docs/BUILD_INSTALL.md)
* [Product Requirements & Compliance Specs (CRA & NIS2)](docs/REQUIREMENTS_AND_COMPLIANCE.md)
* [Technical Implementation Specification](docs/TECHNICAL_SPECIFICATION.md)
* [Configuration & Script Specs](docs/CONFIG.md)
* [Host Hardening Profiles (AppArmor, Systemd)](docs/SECURITY_HARDENING.md)
* [Integration Testing & Threat Simulation Playbook](docs/operations/TESTING_AND_SIMULATION.md)


# runsc-sentry-guard

An ultra-lightweight, out-of-band active incident response daemon 
for `runsc` (gVisor) sandboxes written in Rust.

> ⚠️ **Development Status: ALPHA** 
> 
> DO NOT USE in production environments yet!

## 1. Executive Summary & Core Concept (the TL;DR)

Imagine your application is running inside a high-security vault 
(which is what a gVisor container is). While the vault is designed to
prevent an adversary from easily taking over your entire server, 
it doesn't automatically stop them from making a mess *inside* the container 
if they find a loophole in your app or manage to deploy a zero-day exploit.

`runsc-sentry-guard` is like an **automated, invisible security guard** 
that stands outside that vault. It safely listens to the vault's internal 
diagnostic chatter from the host side without ever stepping foot inside.

The moment it senses anyone trying to do something malicious 
inside your container, like launching a forbidden terminal shell or setting 
up a hidden hacking tool, the guard takes action automatically:

*   **Freeze the Threat:** It instantly locks down and pauses the compromised 
container so the intruder's scripts can't even execute a single line of automated code.
*   **Air-Gap the Network:** It snaps a digital shield around the container's network, 
preventing the intruder from stealing data or attacking other services.
*   **Save the Evidence:** It takes a forensic snapshot of the container's 
memory and file system so your team can investigate exactly how the intruder got in.
*   **Ring the Alarm:** It dispatches structured audit logs straight to your security 
operations team or sounds the alarm via webhooks.


> **Our Mission: Provide Open and Free Enterprise Grade Cyber Defense for Everyone**
> 
> While the operational abstraction is kept as straightforward 
> as possible for administrators, the underlying runtime engine 
> is engineered to satisfy strict regulatory compliance 
> flight-checks (including NIS2, DORA, and the Cyber Resilience Act).
> 


### Why this should matter to you:

Traditional security tools sit *inside* the container alongside your app. 
If an intruder gets root access, they can simply blind, trick, or turn off 
the security tool.

Because `runsc-sentry-guard` operates entirely **out-of-band** (from the outside host edge), 
the workload has zero visibility into the guard daemon. To an intruder, the guard is 
completely invisible, tamper-proof, and impossible to bypass. 

Our goal is to provide even beginner administrators enterprise-grade, real-time 
cyber response capabilities with **zero** performance impact on their running applications.

### Turnkey Quick Start (Run in 60 Seconds)

For rapid evaluations on staging instances, you can bypass native toolchain 
compilation entirely by fetching our pre-compiled release artifacts directly.

> **Platform Compatibility Warning:** These turnkey commands and real-time containment loops require a native Linux operating system. Attempting to run this binary directly on a macOS terminal or Windows PowerShell prompt will invoke our safe simulation layer (`[DEV-MOCK]`) rather than executing active host firewall or container mutations.
>

```bash
# 1. Grab the latest stable release asset and sample manifests
curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/runsc-sentry-guard
curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/config.toml.example
curl -L -O https://github.com/mutex7c/runsc-sentry-guard/releases/latest/download/rules.json.example

# 2. Initialize your secure decoupled blueprints
mv config.toml.example config.toml
mv rules.json.example rules.json

# 3. Arm the executable and start out-of-band monitoring
chmod +x runsc-sentry-guard
sudo ./runsc-sentry-guard config.toml
```

## 2. Motivation

While `runsc` (gVisor) provides exceptional kernel-level isolation for 
containers, traditional container detection tools 
often struggle or introduce unnecessary performance 
overhead when trying to intercept deep sandbox system calls. 

When a container running inside a runsc profile experiences an 
exploit, it generates various Indicators Of Compromise (IOC) 
inside the host-side debug streams. `runsc-sentry-guard` intercepts 
these events out-of-band directly from the host edge. 

It completely bypasses the need for complex 
kernel-hooking architectures (like eBPF) or intrusive container 
modifications, enabling real-time, zero-dependency 
active containment.

## 3. Architectural Design Philosophy

`runsc-sentry-guard` challenges traditional container security conventions. 
By shifting the defense boundary from inside the workload to the host edge, it fixes 
the visibility and latency flaws inherent in legacy detection tools.

| Defensive Vector       | Traditional Agent Approaches                                                                                                                                                                                                                                                                                                                          | runsc-sentry-guard Architecture                                                                                                                                                                                                          |
|:-----------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Isolation Boundary** | **In-Workload Shims / Sidecars:** Run inside or attached to the container. If an attacker achieves container escape or root privilege, the security agent can be blinded, tampered with, or killed.                                                                                                                                                   | **Out-of-Band (Host Edge):** Operates completely decoupled at the host user-space layer. The sandboxed workload has zero visibility into the guard daemon, making it tamper-proof.                                                       |
| **Response Latency**   | **Passive Logging & Triage:** Collects events, streams them to a centralized SIEM, and waits for human security engineers to execute a script or manually isolate the infrastructure.                                                                                                                                                                 | **Active Automated Mitigation:** Bridges detection and containment into a single real-time loop. It mutates host firewalls and freezes task states the moment a signature is detected.                                                   |
| **Concurrency Scale**  | **Monolithic Event FIFO Queues:** Processes incoming logs sequentially. A single high-volume attack or a hanging mitigation script can block the entire event pipeline for adjacent workloads.                                                                                                                                                        | **Key-Based Serialization:** Spawns isolated, independent worker threads pinned to unique Container IDs. A complex containment routine on container A never stalls defenses for container B.                                             |
| **Ingestion Latency**  | **Disk Log Tailers:** Relies on gVisor writing `.boot` files to the host storage layer, introducing minor filesystem write overhead and potential TOCTOU (Time-of-Check to Time-of-Use) security latency. This option is supported by `runsc-sentry-guard` for testing, but UDS Stream Receiver / Socket Mode is strictly recommended for production. | **UDS Stream Receiver:** Bypasses host disk I/O completely. Runtimes stream telemetry straight into the daemon's user-space memory, dropping response latency to sub-millisecond intervals and eliminating disk-spoofing risks entirely. |

> **The Unix Philosophy: Do One Thing and Do It Well**
>
> Instead of attempting to be a bloated, monolithic "Swiss Army knife" agent that 
> tries to handle everything from static vulnerability scanning to compliance auditing, 
> `runsc-sentry-guard` focuses strictly on a single, clear objective: **ultra-low-latency, 
> out-of-band threat containment for docker gVisor sandboxes**.
>
> We do not attempt to reinvent the wheel. The daemon purposefully delegates base firewall 
> policy rulesets to `nftables`, background process management to `systemd`, and application 
> isolation to `runsc`. By maintaining this functional focus, we keep 
> a lean footprint, a minimized attack surface, and real-time containment speed.

## 4. Core Documentation & Context Links

* [Source Compilation & System Installation Guide](docs/BUILD_INSTALL.md)
* [Product Requirements & Compliance Specs (CRA & NIS2)](docs/REQUIREMENTS_AND_COMPLIANCE.md)
* [Technical Implementation Specification](docs/TECHNICAL_SPECIFICATION.md)
* [Configuration & Script Specs](docs/CONFIG.md)
* [Host Hardening Profiles (AppArmor, Systemd)](docs/SECURITY_HARDENING.md)
* [Integration Testing & Threat Simulation Playbook](docs/operations/TESTING_AND_SIMULATION.md)


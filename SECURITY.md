# Security Policy

## Supported Versions

We actively monitor and maintain security updates for the following versions of `runsc-sentry-guard`. Vulnerabilities discovered in unsupported or modified forks will not be triaged under this policy.

| Version | Supported         |
|---------|-------------------|
| v0.1.x  | 🟢 Active (Alpha) |
| < v0.1  | ❌ Unsupported     |

## Reporting a Vulnerability

**DO NOT open a public GitHub Issue for suspected or verified security vulnerabilities.**

If you discover a memory exploit, capability leak, sandbox bypass, or a remote code execution (RCE) flaw within this daemon, please report it via the **GitHub Private Vulnerability Reporting:** 

Navigate to the [Security tab](https://github.com/mutex7c/runsc-sentry-guard/security) of this repository, and select **Report a vulnerability**. This allows you to privately discuss and coordinate a patch with the maintainers inside an isolated draft advisory space.

### What to Include in a Report
To ensure a rapid triage process, please include as much technical telemetry as possible:
* A detailed description of the flaw, its architectural vector (e.g., log stream parsing bypass, seccomp collision, thread synchronization race condition).
* A complete Proof of Concept (PoC) script, raw log sample mutation, or a reproducible environment profile.
* An assessment of the localized host threat impact (e.g., privilege escalation, daemon denial-of-service, unintended containment bypass).

## Our Security Response Commitment

Upon receiving a valid vulnerability notification, the `runsc-sentry-guard` maintainers pledge to execute the following coordinated timeline:

1. **Acknowledgment:** We will confirm receipt of your report within **48 hours**.
2. **Triage & Evaluation:** We will validate the flaw and coordinate code modifications inside a private workspace within **10 days**.
3. **Coordinated Disclosure:** We aim to release an official security patch advisory and an updated compiled tag release within **15 days** of validation. We respectfully request that you refrain from disclosing the exploit vectors publicly until users have been given a reasonable window to patch their running production nodes.

Thank you for helping keep the cloud-native ecosystem safe and isolated!
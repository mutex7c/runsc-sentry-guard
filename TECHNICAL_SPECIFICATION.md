# Detailed Technical Specification: runsc-sentry-guard (v1.0.0-Spec)

## 1. System Constants & Execution Scope Defaults

To satisfy Filesystem Hierarchy Standards (FHS) and ensure operational host safety, the daemon enforces the following hardcoded platform boundary rules:

* **Default Configuration Path:** `/etc/runsc-sentry-guard/config.toml`
* **Default gVisor Log Target Directory:** `/var/log/gvisor/`
* **Log File Match Extension:** The global directory crawler tracks files terminating strictly in `.boot` for system call stream evaluation.
* **Internal State Tick Rate:** `1000ms` (The frequency threshold for running `getdents64` loops to evaluate directory changes and poll active file descriptors).
* **Maximum In-Memory Log Buffer Line Ceiling:** `8192 bytes`. The ingestion stream engine processes chunks up to this maximum limit per line evaluation. Single segments extending past this boundary without a newline delimiter are flagged as an anomaly to safeguard host memory channels against buffer-bloat denial-of-service actions.

## 2. Configuration Schema Specification (`config.toml`)

The parsing engine uses a declarative, strict-typing deserializer enforced via `#[serde(deny_unknown_fields)]`. If an unmapped, malformed, or deprecated structural property is encountered during initialization, the daemon will gracefully abort boot routines and output a validation schema error.

```toml
[monitor]
log_dir = "/var/log/gvisor/"
check_interval_ms = 1000
ip_whitelist = ["127.0.0.1/32", "10.11.11.0/24", "192.168.3.0/24"]
nftables_default_table = "inet security_ops"
json_logging_enabled = true

[[rules]]
name = "unauthorized_interactive_shells"
regex_match = ' execve\(.*(bash|sh|zsh|dash|nc|ncat|socat)'

[[rules.try_actions]]
type = "validate_state"

[[rules.try_actions]]
type = "pause"

[[rules.try_actions]]
type = "commit_snapshot"
prefix = "forensic-snapshot"

[[rules.try_actions]]
type = "nft_blacklist"
set_name = "container_blacklist"
timeout = "24h"

[[rules.try_actions]]
type = "restart"

[[rules.try_actions]]
type = "unpause"

[[rules.final_actions]]
type = "log_critical"

[[rules.final_actions]]
type = "container_signal"
signal = "SIGKILL"

[[rules.final_actions]]
type = "nft_blacklist"
set_name = "container_blacklist"
timeout = "168h"
```
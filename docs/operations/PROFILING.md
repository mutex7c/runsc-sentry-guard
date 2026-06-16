# Performance Profiling & Flamegraph Telemetry

This document outlines the standard operating procedure for generating CPU flamegraphs 
to detect lock contention, micro-stutters, and user-to-kernel context switching delays 
under extreme incident ingestion loads.

## 1. Prerequisites

To capture stack trace and contention data, install the Rust flamegraph profiler on your test node:

```bash
cargo install flamegraph
```

*Note: Ensure your Linux host has the core `perf` subsystem installed 
(e.g., `sudo apt install linux-tools-common linux-tools-generic` on Ubuntu/Debian).*

## 2. Telemetry Capture Execution

Launch the daemon explicitly under the profiler with root capabilities 
so `perf` can successfully hook into the kernel tracepoints and UDS socket bindings:

```bash
sudo cargo flamegraph --root --bin runsc-sentry-guard
```

## 3. Load Simulation

While the profiler is actively tracing the daemon in the foreground, open a separate privileged terminal session and execute the load-testing bash scripts located in this directory:

```bash
sudo ./scripts/test_file_flood.sh
sudo ./scripts/test_uds_flood.sh
```

## 4. Teardown & Interpretation

Once the load scripts finish generating their respective spoofing floods, send a `SIGINT` (`Ctrl+C`) to the running daemon.

The `cargo-flamegraph` utility will automatically aggregate the stack traces and compile an interactive `flamegraph.svg` vector file in your current working directory.

### How to Read the Results

Open `flamegraph.svg` in any modern web browser to interact with the stack frames.

* **Identifying Contention:** Look specifically at the width of the `parking_lot::Mutex` acquisition frames.
* **The Threshold:** If the `parking_lot` mutex represents a true CPU bottleneck under our Anti-DoS spoofing floods, you will see a massive, flat visual plateau spanning the width of the graph over `lock_slow` or `futex_wait`.
* **Actionable Next Steps:** If these contention frames represent a significant percentage of total CPU time, the engine should be decoupled to use a lock-free `AtomicU64` Compare-And-Swap (CAS) architecture. If they are negligible, the user-space spinlocks are sufficient.
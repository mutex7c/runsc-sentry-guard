// Application Entry point
// Orchestrates process initialization, ambient capability stripping, and seccomp jail loading.

mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use tailer::start_monitor_loop;

fn main() {
    // Enforcement Boundary: Validate active Linux root execution privileges explicitly
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "Fatal System Error: runsc-sentry-guard must execute as root to manage network filters."
            );
            std::process::exit(1);
        }
    }

    println!("[INFO] Initializing runsc-sentry-guard active containment runtime architecture...");

    let production_path = "/etc/runsc-sentry-guard/config.toml";
    let developer_path = "config.toml";

    let active_path = if Path::new(production_path).exists() {
        production_path
    } else {
        developer_path
    };

    match load_config(active_path) {
        Ok(valid_config) => {
            let json_enabled = valid_config.monitor.json_logging_enabled;

            logger::emit_log(
                "INFO",
                "initialization",
                None,
                None,
                None,
                None,
                "ARMED",
                &format!(
                    "Configuration profile verification successful via path: {}",
                    active_path
                ),
                json_enabled,
            );

            // Permanently lock down permitted POSIX capabilities and drop DAC overrides
            #[cfg(target_os = "linux")]
            drop_privileges(json_enabled);

            // Hand execution layers gracefully onto multithreaded monitoring handlers
            start_monitor_loop(valid_config);
        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

// Permanently strips root identity (UID 0) and clips process capabilities strictly down to CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
fn drop_privileges(json_enabled: bool) {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    // Phase 1: Inform kernel to preserve permitted capability boundaries across the identity shift
    unsafe {
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            eprintln!("Fatal System Error: prctl(PR_SET_KEEPCAPS) invocation rejected by kernel.");
            std::process::exit(1);
        }
    }

    // Clear all ambiently inherited privileges prior to seeding constraints
    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        eprintln!(
            "[WARN] Failed to wipe ambient initialization capabilities: {:?}",
            e
        );
    }

    let mut structural_capabilities = HashSet::new();
    structural_capabilities.insert(Capability::CAP_NET_ADMIN);

    // Phase 2: Secure Permitted and Inheritable caps while still running as root
    if let Err(e) = caps::set(None, CapSet::Permitted, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!(
                "Fatal security boundary breakdown lowering permitted sets: {:?}",
                e
            ),
            json_enabled,
        );
        std::process::exit(1);
    }

    if let Err(e) = caps::set(None, CapSet::Inheritable, &structural_capabilities) {
        eprintln!("Failed to set Inheritable capabilities: {:?}", e);
        std::process::exit(1);
    }

    // Phase 3: Shed root user identity (UID 0) permanently by transitioning to 'nobody' (65534)
    unsafe {
        let target_uid = 65534; // nobody
        let target_gid = 65534; // nobody

        if libc::setresgid(target_gid, target_gid, target_gid) != 0 ||
            libc::setresuid(target_uid, target_uid, target_uid) != 0 {
            logger::emit_log(
                "ERROR",
                "initialization",
                None,
                None,
                None,
                Some("privilege_drop"),
                "CRASH",
                "Fatal security failure: Identity shift to unprivileged user (nobody) rejected.",
                json_enabled,
            );
            std::process::exit(1);
        }
    }

    // Phase 4: Re-assert CAP_NET_ADMIN into Effective and Ambient sets (cleared natively on UID swap)
    if let Err(e) = caps::set(None, CapSet::Effective, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!(
                "Fatal security boundary breakdown establishing effective sets post identity shift: {:?}",
                e
            ),
            json_enabled,
        );
        std::process::exit(1);
    }

    if let Err(e) = caps::set(None, CapSet::Ambient, &structural_capabilities) {
        eprintln!("Failed to re-assert Ambient capabilities post identity shift: {:?}", e);
        std::process::exit(1);
    }

    logger::emit_log(
        "INFO",
        "initialization",
        None,
        None,
        None,
        Some("privilege_drop"),
        "SUCCESS",
        "Process identity dropped to nobody (UID 65534); security scope pinned strictly to CAP_NET_ADMIN.",
        json_enabled,
    );
}
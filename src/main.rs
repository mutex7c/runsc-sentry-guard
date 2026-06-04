mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use tailer::start_monitor_loop;

fn main() {
    // Enforcement Boundary: Verify Linux root execution privileges

    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "Fatal Error: runsc-sentry-guard must run explicitly as root to interact with nftables/docker namespaces."
            );
            std::process::exit(1);
        }
    }

    println!("[INFO] Launching runsc-sentry-guard runtime architecture initialization... ");

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
                    "Configuration profiles loaded cleanly via path target: {}",
                    active_path
                ),
                json_enabled,
            );

            // Restrict process boundary privilege lines right before starting I/O

            #[cfg(target_os = "linux")]
            drop_privileges(json_enabled);

            // Hand off execution loops to the monitor thread framework

            start_monitor_loop(valid_config);
        }

        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

/// Permanently drops all ambient, permitted, and effective POSIX capabilities
/// except for CAP_NET_ADMIN to insulate the host environment against code-injection escalations.
#[cfg(target_os = "linux")]
fn drop_privileges(json_enabled: bool) {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    // Completely clear out ambient capabilities passed by outer shells

    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        eprintln!(
            "[WARN] Failed to clear ambient system capabilities: {:?}",
            e
        );
    }

    // Define the absolute minimum operational capability boundary set

    let mut structural_capabilities = HashSet::new();
    structural_capabilities.insert(Capability::CAP_NET_ADMIN);

    // Enforce the effective restriction map

    if let Err(e) = caps::set(None, CapSet::Effective, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!("Fatal security failure dropping effective sets: {:?}", e),
            json_enabled,
        );
        std::process::exit(1);
    }

    // Tighten the permitted system capability bounds

    if let Err(e) = caps::set(None, CapSet::Permitted, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!("Fatal security failure dropping permitted sets: {:?}", e),
            json_enabled,
        );
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
        "Process shed ambient root access. Bound context safely to host CAP_NET_ADMIN.",
        json_enabled,
    );
}

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

    println!("[INFO] Launching runsc-sentry-guard runtime architecture initialization...");

    // Determine target configuration file scope based on environmental placement

    let production_path = "/etc/runsc-sentry-guard/config.toml";
    let developer_path = "config.toml";

    let active_path = if Path::new(production_path).exists() {
        production_path
    } else {
        developer_path
    };

    // Attempt fail-safe load of configuration parameters

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

            // Hand off execution loops to the monitor thread framework

            start_monitor_loop(valid_config);
        }

        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

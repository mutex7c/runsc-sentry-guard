// Application Entry point
// Orchestrates process initialization and routes execution to the multithreaded monitoring handlers

mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tailer::start_monitor_loop;

fn main() {
    // Enforcement Boundary: Validate active Linux root execution privileges explicitly
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "Fatal System Error: runsc-sentry-guard must execute as root to manage network filters and access host streams."
            );
            std::process::exit(1);
        }
    }

    println!("[INFO] Initializing runsc-sentry-guard active containment runtime architecture...");

    let shutdown_requested = Arc::new(AtomicBool::new(false));

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

            install_shutdown_signal_handlers(Arc::clone(&shutdown_requested), json_enabled);

            // Hand execution layers gracefully onto multithreaded monitoring handlers
            start_monitor_loop(valid_config, shutdown_requested);

            worker::cleanup_firewall_drops(json_enabled);

            logger::emit_log(
                "INFO",
                "shutdown",
                None,
                None,
                None,
                None,
                "COMPLETE",
                "Graceful shutdown sequence completed.",
                json_enabled,
            );
        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

fn install_shutdown_signal_handlers(shutdown_requested: Arc<AtomicBool>, json_enabled: bool) {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    for (signal, signal_name) in [(SIGTERM, "SIGTERM"), (SIGINT, "SIGINT")] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown_requested)) {
            logger::emit_log(
                "ERROR",
                "initialization",
                None,
                None,
                None,
                Some("signal_handler"),
                "CRASH",
                &format!("Failed to register {} shutdown handler: {}", signal_name, e),
                json_enabled,
            );
            std::process::exit(1);
        }
    }
}

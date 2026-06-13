// Application Entry point

// Orchestrates process initialization and routes execution to the multithreaded monitoring handlers

mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use tailer::start_monitor_loop;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

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

    let shutdown = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .expect("Fatal System Initialization Error: Failed to register SIGINT lifecycle hook.");
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .expect("Fatal System Initialization Error: Failed to register SIGTERM lifecycle hook.");

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

            let flush_firewall = valid_config.monitor.flush_firewall_on_shutdown;
            let nft_table = valid_config.monitor.nftables_default_table.clone();
            let mut sets_to_flush = Vec::new();

            for rule in &valid_config.rules {
                let combined_actions = rule.try_actions.iter().chain(rule.final_actions.iter());
                for action in combined_actions {
                    if let config::AtomicAction::NftBlacklist { set_name, .. } = action {
                        sets_to_flush.push(set_name.clone());
                    }
                }
            }

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

            // Trigger the post-crash recovery engine during bootstrap
            // initialization before spinning up core processing tracking loops
            cleanup_stale_firewall_elements(&valid_config);
            
            start_monitor_loop(valid_config, Arc::clone(&shutdown), active_path.to_string());

            logger::emit_log(
                "INFO",
                "shutdown",
                None,
                None,
                None,
                None,
                "HALTED",
                "Decommissioning sequence initialized. Processing cleanup contexts.",
                json_enabled,
            );

            if flush_firewall {
                for set_name in sets_to_flush {
                    let status = std::process::Command::new("nft")
                        .arg("flush")
                        .arg("set")
                        .args(nft_table.split_whitespace())
                        .arg(&set_name)
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            println!("[INFO] Graceful Shutdown: Cleared firewall containment set '{}'.", set_name);
                        }
                        _ => {
                            eprintln!("[WARN] Graceful Shutdown: Failed to flush firewall set '{}'.", set_name);
                        }
                    }
                }
            }

        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

// Post-Crash Recovery Bootstrap Engine

// Scans configured nftables sets at startup, identifies elements
// carrying "runsc-sentry-guard" tracking comment, and purges them to prevent stale drifts
fn cleanup_stale_firewall_elements(config: &config::GuardConfig) {
    let table = &config.monitor.nftables_default_table;
    // Bounded regex tracking standard IPv4 and simplified IPv6 formatting tokens
    let ip_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|([a-fA-F0-9:]+:+[a-fA-F0-9:]+)\b").unwrap();

    for rule in &config.rules {
        let combined_actions = rule.try_actions.iter().chain(rule.final_actions.iter());
        for action in combined_actions {
            if let config::AtomicAction::NftBlacklist { set_name, .. } = action {
                // Query the exact host-side state configuration of the targeted set
                let output = std::process::Command::new("nft")
                    .arg("list")
                    .arg("set")
                    .args(table.split_whitespace())
                    .arg(set_name)
                    .output();

                if let Ok(out) = output {
                    let stdout_str = String::from_utf8_lossy(&out.stdout);
                    for line in stdout_str.lines() {
                        // Isolate elements dropped by our daemon during a previous crashed lifecycle run
                        if line.contains("comment \"runsc-sentry-guard\"") {
                            if let Some(caps) = ip_regex.captures(line) {
                                if let Some(matched_ip) = caps.get(0) {
                                    let ip_str = matched_ip.as_str();
                                    let element_payload = format!("{{ {} }}", ip_str);

                                    // Remove the individual stale element value cleanly from the set
                                    let _ = std::process::Command::new("nft")
                                        .arg("delete")
                                        .arg("element")
                                        .args(table.split_whitespace())
                                        .arg(set_name)
                                        .arg(&element_payload)
                                        .status();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

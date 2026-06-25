mod config;
mod ingestion;
mod limiters;
mod logger;
mod socket;
mod worker;

use config::{load_and_merge_manifests, load_config};
use ingestion::{compile_manifest_rules, run_offline_reprocessing, start_monitor_loop};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_offline_mode = args.contains(&"--reprocess-logs".to_string());
    let force_json_output = args.contains(&"--output-json".to_string());
    let hide_bypasses = args.contains(&"--hide-bypasses".to_string());

    let offline_map_path = args
        .iter()
        .position(|a| a == "--offline-mapping")
        .and_then(|idx| args.get(idx + 1).cloned());

    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("Fatal System Error: runsc-sentry-guard must execute as root.");
            std::process::exit(1);
        }
    }

    if is_offline_mode {
        println!("[INFO] Starting runsc-sentry-guard in OFFLINE FORENSIC MODE...");
    } else {
        println!(
            "[INFO] Initializing runsc-sentry-guard active containment runtime architecture..."
        );
    }

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
        Ok(mut valid_config) => {
            if is_offline_mode {
                valid_config.monitor.json_logging_enabled = force_json_output;
            } else if force_json_output {
                valid_config.monitor.json_logging_enabled = true;
            }

            let json_enabled = valid_config.monitor.json_logging_enabled;
            let log_level = valid_config.monitor.log_level;
            let flush_firewall = valid_config.monitor.flush_firewall_on_shutdown;
            let nft_table = valid_config.monitor.nftables_default_table.clone();

            match load_and_merge_manifests(&valid_config.monitor.security_manifest_paths) {
                Ok((global_playbooks, global_rules, global_whitelists, global_mappings)) => {
                    if is_offline_mode {
                        let compiled_rules = compile_manifest_rules(
                            &global_rules,
                            &global_whitelists,
                            &global_playbooks,
                            global_mappings,
                        );

                        run_offline_reprocessing(
                            &valid_config,
                            &compiled_rules,
                            json_enabled,
                            offline_map_path,
                            hide_bypasses,
                        );
                        std::process::exit(0);
                    }

                    let mut sets_to_flush = Vec::new();
                    for playbook in global_playbooks.values() {
                        let combined_actions = playbook
                            .try_actions
                            .iter()
                            .chain(playbook.final_actions.iter());

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
                            "Configuration profile and security manifests verified successfully via path: {}",
                            active_path
                        ),
                        log_level,
                        json_enabled,
                    );

                    worker::cleanup_stale_firewall_elements(
                        &valid_config,
                        &global_rules,
                        &global_playbooks,
                    );

                    start_monitor_loop(
                        valid_config,
                        global_playbooks,
                        global_rules,
                        global_whitelists,
                        global_mappings,
                        Arc::clone(&shutdown),
                        active_path.to_string(),
                    );

                    logger::emit_log(
                        "INFO",
                        "shutdown",
                        None,
                        None,
                        None,
                        None,
                        "HALTED",
                        "Decommissioning sequence initialized. Processing cleanup contexts.",
                        log_level,
                        json_enabled,
                    );

                    if flush_firewall {
                        for set_name in sets_to_flush {
                            let status = std::process::Command::new("/usr/sbin/nft")
                                .arg("flush")
                                .arg("set")
                                .args(nft_table.split_whitespace())
                                .arg(&set_name)
                                .status();

                            match status {
                                Ok(s) if s.success() => {
                                    println!(
                                        "[INFO] Graceful Shutdown: Cleared firewall containment set '{}'.",
                                        set_name
                                    );
                                }
                                _ => {
                                    eprintln!(
                                        "[WARN] Graceful Shutdown: Failed to flush firewall set '{}'.",
                                        set_name
                                    );
                                }
                            }
                        }
                    }
                }
                Err(err_msg) => {
                    eprintln!(
                        "System Architectural Boot Panic: Manifest integrity verification failed: {}",
                        err_msg
                    );
                    std::process::exit(1);
                }
            }
        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

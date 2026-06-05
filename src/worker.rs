// Containment Mitigation Engine
// Invokes localized host sandboxing isolation binaries and commands safely.

use crate::config::AtomicAction;
use crate::logger::emit_log;
use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;

pub fn is_ip_safe(target_ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    whitelist.iter().any(|network| network.contains(target_ip))
}

pub fn resolve_container_ip(container_id: &str, json_enabled: bool) -> Option<IpAddr> {
    let output = Command::new("docker")
        .args(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_id,
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let ip_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if ip_str.is_empty() {
                return None;
            }
            ip_str.parse::<IpAddr>().ok()
        }
        _ => {
            emit_log(
                "WARN",
                "worker_engine",
                None,
                Some(container_id),
                None,
                Some("resolve_ip"),
                "FAILURE",
                "Failed to query Docker socket for networking metadata.",
                json_enabled,
            );
            None
        }
    }
}

fn execute_atomic_command(
    action: &AtomicAction,
    container_id: &str,
    whitelist: &[IpNet],
    table: &str,
    json_enabled: bool,
) -> Result<(), String> {
    match action {
        AtomicAction::WebhookAlert { url } => {
            let payload = format!(
                "{{\"text\":\"🚨 [SENTRY-GUARD] Active containment pipeline triggered for container context: {}\"}}",
                container_id
            );
            let s = Command::new("curl")
                .args(&[
                    "-X",
                    "POST",
                    "-H",
                    "Content-type: application/json",
                    "--data",
                    &payload,
                    url,
                ])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Webhook dispatch returned failure code.".into())
            }
        }

        AtomicAction::ValidateState => {
            let output = Command::new("docker")
                .args(&["inspect", "-f", "{{.State.Running}}", container_id])
                .output()
                .map_err(|e| e.to_string())?;
            if String::from_utf8_lossy(&output.stdout).trim() == "true" {
                Ok(())
            } else {
                Err("Target container context reported stopped status.".into())
            }
        }

        AtomicAction::Pause => {
            let s = Command::new("docker")
                .args(&["pause", container_id])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Docker pause manipulation rejected.".into())
            }
        }

        AtomicAction::Unpause => {
            let s = Command::new("docker")
                .args(&["unpause", container_id])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Docker unpause manipulation rejected.".into())
            }
        }

        AtomicAction::Restart => {
            let s = Command::new("docker")
                .args(&["restart", container_id])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Docker restart execution rejected.".into())
            }
        }

        AtomicAction::CommitSnapshot { prefix } => {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let target_tag = format!("{}-{}-{}", prefix, container_id, timestamp);
            let s = Command::new("docker")
                .args(&["commit", container_id, &target_tag])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Forensic image snapshot generation failed.".into())
            }
        }

        AtomicAction::ContainerSignal { signal } => {
            let s = Command::new("docker")
                .args(&["kill", &format!("--signal={}", signal), container_id])
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Linux signal allocation injection failed.".into())
            }
        }

        AtomicAction::NftBlacklist { set_name, timeout } => {
            if let Some(ip) = resolve_container_ip(container_id, json_enabled) {
                if is_ip_safe(&ip, whitelist) {
                    emit_log(
                        "WARN",
                        "worker_engine",
                        None,
                        Some(container_id),
                        Some(&ip.to_string()),
                        Some("nft_blacklist"),
                        "INTERCEPTED",
                        "Target IP matches core infrastructure whitelist. Isolation aborted.",
                        json_enabled,
                    );
                    return Ok(());
                }
                execute_firewall_mutation(&ip.to_string(), set_name, timeout, table)?;
                emit_log(
                    "CRITICAL",
                    "worker_engine",
                    None,
                    Some(container_id),
                    Some(&ip.to_string()),
                    Some("nft_blacklist"),
                    "SUCCESS",
                    &format!(
                        "Target network isolated via set {} for duration context {}",
                        set_name, timeout
                    ),
                    json_enabled,
                );
            }
            Ok(())
        }

        AtomicAction::RunCustomScript { path } => {
            let s = Command::new(path)
                .arg(container_id)
                .status()
                .map_err(|e| e.to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("Custom automated automation extension script crashed.".into())
            }
        }

        AtomicAction::LogJson => {
            emit_log(
                "INFO",
                "worker_engine",
                None,
                Some(container_id),
                None,
                Some("log_json"),
                "AUDIT",
                "Standard signature verification telemetry logged.",
                json_enabled,
            );
            Ok(())
        }

        AtomicAction::LogCritical => {
            emit_log(
                "CRITICAL",
                "worker_engine",
                None,
                Some(container_id),
                None,
                Some("log_critical"),
                "ALERT",
                "Security policy remediation loop engaged.",
                json_enabled,
            );
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn execute_firewall_mutation(
    ip: &str,
    set: &str,
    timeout: &str,
    table: &str,
) -> Result<(), String> {
    // Clean Fix: Import located strictly within target compilation block scope to erase linter warnings
    use regex::Regex;

    let validation_rule = Regex::new(r"^\d+[smhd]$").unwrap();
    if !validation_rule.is_match(timeout) {
        return Err(format!(
            "Security Constraint Violation: Intercepted malformed firewall duration payload: '{}'",
            timeout
        ));
    }

    let s = Command::new("nft")
        .args(&[
            "add",
            "element",
            table,
            set,
            &format!("{{ {} timeout {} }}", ip, timeout),
        ])
        .status()
        .map_err(|e| e.to_string())?;

    if s.success() {
        Ok(())
    } else {
        Err("Kernel nftables transaction rejected execution parameters.".into())
    }
}

#[cfg(not(target_os = "linux"))]
fn execute_firewall_mutation(
    ip: &str,
    set: &str,
    timeout: &str,
    table: &str,
) -> Result<(), String> {
    println!(
        "[DEV-MOCK-FIREWALL] Appending Rule Logic to [Table: {}, Set: {}, Timeout: {}] -> Drop Target IP: {}",
        table, set, timeout, ip
    );
    Ok(())
}

pub fn execute_containment_pipeline(
    container_id: String,
    try_actions: Vec<AtomicAction>,
    final_actions: Vec<AtomicAction>,
    whitelist: Vec<IpNet>,
    table: String,
    json_enabled: bool,
    rule_name: String,
) {
    let mut pipeline_failed = false;

    for action in &try_actions {
        if let Err(e) =
            execute_atomic_command(action, &container_id, &whitelist, &table, json_enabled)
        {
            emit_log(
                "WARN",
                "worker_engine",
                Some(&rule_name),
                Some(&container_id),
                None,
                Some(&format!("{:?}", action)),
                "FAILURE",
                &format!("Primary playbook action failed structural context: {}", e),
                json_enabled,
            );
            pipeline_failed = true;
            break;
        }
    }

    if pipeline_failed {
        emit_json_escalation_marker(&container_id, &rule_name, json_enabled);
        for fallback in &final_actions {
            if let Err(fallback_error) =
                execute_atomic_command(fallback, &container_id, &whitelist, &table, json_enabled)
            {
                emit_log(
                    "CRITICAL",
                    "worker_engine",
                    Some(&rule_name),
                    Some(&container_id),
                    None,
                    Some(&format!("{:?}", fallback)),
                    "CRASH",
                    &format!("EMERGENCY CONTAINMENT FAILURE: {}", fallback_error),
                    json_enabled,
                );
            }
        }
    }
}

fn emit_json_escalation_marker(container_id: &str, rule: &str, json_enabled: bool) {
    emit_log(
        "CRITICAL",
        "worker_engine",
        Some(rule),
        Some(container_id),
        None,
        Some("escalation_routing"),
        "ENGAGED",
        "Primary playbook failed structural strategy. Deploying fallback containment actions.",
        json_enabled,
    );
}

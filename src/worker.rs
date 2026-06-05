// Containment Mitigation Engine
// Invokes localized host sandboxing isolation techniques and direct socket interactions safely.

use crate::config::AtomicAction;
use crate::logger::emit_log;
use ipnet::IpNet;
use std::process::Command;

// Platform-Gated Imports: Prevents unused import warnings on non-Linux environments
#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

// Linux Production Models: Gated completely to prevent unconstructed struct alerts on non-Linux systems
#[derive(Deserialize)]
#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
struct DockerNetworkInterface {
    IPAddress: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
struct DockerNetworkSettings {
    Networks: HashMap<String, DockerNetworkInterface>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
struct DockerInspectResponse {
    NetworkSettings: DockerNetworkSettings,
}

/// Zero-Fork Native HTTP Over Unix Domain Socket Engine (Linux Production Mode Only)
#[cfg(target_os = "linux")]
fn execute_docker_uds_request(
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    use std::io::{BufReader, Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect("/var/run/docker.sock")
        .map_err(|e| format!("Docker Socket Connection Refused: {}", e))?;

    let request_payload = if let Some(b) = body {
        format!(
            "{} {} HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            method,
            path,
            b.len(),
            b
        )
    } else {
        format!("{} {} HTTP/1.0\r\n\r\n", method, path)
    };

    stream
        .write_all(request_payload.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut response_raw = String::new();
    let mut reader = BufReader::new(stream).take(65536);
    reader
        .read_to_string(&mut response_raw)
        .map_err(|e| e.to_string())?;

    let response_parts: Vec<&str> = response_raw.splitn(2, "\r\n\r\n").collect();
    if response_parts.is_empty() {
        return Err("Received completely empty frame stream from Docker daemon socket.".into());
    }

    let status_line = response_parts[0].lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(500);

    let payload = if response_parts.len() > 1 {
        response_parts[1].to_string()
    } else {
        String::new()
    };

    Ok((status_code, payload))
}

// Firewall Utilities: Gated to Linux to eliminate dead-code diagnostics on development hosts
#[cfg(target_os = "linux")]
pub fn is_ip_safe(target_ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    whitelist.iter().any(|network| network.contains(target_ip))
}

#[cfg(target_os = "linux")]
pub fn resolve_container_ips(container_id: &str, json_enabled: bool) -> Vec<IpAddr> {
    let endpoint = format!("/containers/{}/json", container_id);
    let mut ips = Vec::new();

    match execute_docker_uds_request("GET", &endpoint, None) {
        Ok((status, json_payload)) if status == 200 => {
            if let Ok(parsed) = serde_json::from_str::<DockerInspectResponse>(&json_payload) {
                for network in parsed.NetworkSettings.Networks.values() {
                    if !network.IPAddress.is_empty() {
                        if let Ok(ip) = network.IPAddress.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
        Ok((status, _)) => {
            emit_log(
                "WARN",
                "worker_engine",
                None,
                Some(container_id),
                None,
                Some("resolve_ip"),
                "FAILURE",
                &format!(
                    "Docker socket returned HTTP {} during IP resolution.",
                    status
                ),
                json_enabled,
            );
        }
        Err(e) => {
            emit_log(
                "WARN",
                "worker_engine",
                None,
                Some(container_id),
                None,
                Some("resolve_ip"),
                "FAILURE",
                &format!(
                    "Failed to query Docker socket for networking metadata via UDS channel: {}",
                    e
                ),
                json_enabled,
            );
        }
    }
    ips
}

fn execute_atomic_command(
    action: &AtomicAction,
    container_id: &str,
    whitelist: &[IpNet],
    table: &str,
    json_enabled: bool,
) -> Result<(), String> {
    // Clear variable to allow flawless optimization evaluations across platforms
    let _ = whitelist;

    match action {
        AtomicAction::WebhookAlert { url } => {
            let payload = format!(
                "{{\\\"text\\\":\\\"🚨 [SENTRY-GUARD] Active containment pipeline triggered for container context: {}\\\"}}",
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

        infrastructure_action => {
            #[cfg(target_os = "linux")]
            {
                match infrastructure_action {
                    AtomicAction::ValidateState => {
                        // Deprecated logical check to resolve TOCTOU vulnerability
                        emit_log(
                            "INFO",
                            "worker_engine",
                            None,
                            Some(container_id),
                            None,
                            Some("validate_state"),
                            "SKIPPED",
                            "ValidateState bypassed. Relying natively on downstream atomic Docker API mutations to prevent TOCTOU race conditions.",
                            json_enabled,
                        );
                        Ok(())
                    }

                    AtomicAction::Pause => {
                        let endpoint = format!("/containers/{}/pause", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None)?;
                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            Err(format!(
                                "Pause mutation rejected (HTTP {}): {}",
                                status, err_payload
                            ))
                        }
                    }

                    AtomicAction::Unpause => {
                        let endpoint = format!("/containers/{}/unpause", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None)?;
                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            Err(format!(
                                "Unpause mutation rejected (HTTP {}): {}",
                                status, err_payload
                            ))
                        }
                    }

                    AtomicAction::Restart => {
                        let endpoint = format!("/containers/{}/restart", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None)?;
                        if (200..300).contains(&status) {
                            Ok(())
                        } else {
                            Err(format!(
                                "Restart mutation rejected (HTTP {}): {}",
                                status, err_payload
                            ))
                        }
                    }

                    AtomicAction::CommitSnapshot { prefix } => {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let query_path = format!(
                            "/commit?container={}&repo={}-{}&tag=latest",
                            container_id, prefix, timestamp
                        );
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &query_path, None)?;
                        if (200..300).contains(&status) {
                            Ok(())
                        } else {
                            Err(format!(
                                "CommitSnapshot rejected (HTTP {}): {}",
                                status, err_payload
                            ))
                        }
                    }

                    AtomicAction::ContainerSignal { signal } => {
                        let query_path =
                            format!("/containers/{}/kill?signal={}", container_id, signal);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &query_path, None)?;
                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            Err(format!(
                                "ContainerSignal rejected (HTTP {}): {}",
                                status, err_payload
                            ))
                        }
                    }

                    AtomicAction::NftBlacklist { set_name, timeout } => {
                        let ips = resolve_container_ips(container_id, json_enabled);
                        if ips.is_empty() {
                            return Err("IP resolution yielded zero addresses; cannot apply nftables blacklist.".into());
                        }

                        for ip in ips {
                            if is_ip_safe(&ip, whitelist) {
                                emit_log(
                                    "WARN",
                                    "worker_engine",
                                    None,
                                    Some(container_id),
                                    Some(&ip.to_string()),
                                    Some("nft_blacklist"),
                                    "INTERCEPTED",
                                    "Target IP matches core infrastructure whitelist. Skipping isolation for this specific address.",
                                    json_enabled,
                                );
                                continue;
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
                    _ => unreachable!(),
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                match infrastructure_action {
                    AtomicAction::ValidateState => {
                        println!(
                            "[DEV-MOCK] Verifying runtime operational status for ID: {}",
                            container_id
                        );
                        Ok(())
                    }
                    AtomicAction::Pause => {
                        println!(
                            "[DEV-MOCK] Injecting out-of-band container namespace FREEZE on ID: {}",
                            container_id
                        );
                        Ok(())
                    }
                    AtomicAction::Unpause => {
                        println!(
                            "[DEV-MOCK] Releasing container namespace FREEZE mutation execution on ID: {}",
                            container_id
                        );
                        Ok(())
                    }
                    AtomicAction::Restart => {
                        println!(
                            "[DEV-MOCK] Dispatching rolling container runtime reboot signature to ID: {}",
                            container_id
                        );
                        Ok(())
                    }
                    AtomicAction::CommitSnapshot { prefix } => {
                        println!(
                            "[DEV-MOCK] Committing container snapshot to register using tag: {}-{}",
                            prefix, container_id
                        );
                        Ok(())
                    }
                    AtomicAction::ContainerSignal { signal } => {
                        println!(
                            "[DEV-MOCK] Injecting kernel process termination signal [{}] straight to target ID: {}",
                            signal, container_id
                        );
                        Ok(())
                    }
                    AtomicAction::NftBlacklist { set_name, timeout } => {
                        println!(
                            "[DEV-MOCK] Appending element drop logic -> Table: {}, Set: {}, Duration: {}",
                            table, set_name, timeout
                        );
                        Ok(())
                    }
                    _ => unreachable!(),
                }
            }
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
    use regex::Regex;
    static VALIDATION_RULE: OnceLock<Regex> = OnceLock::new();
    let rule = VALIDATION_RULE.get_or_init(|| Regex::new(r"^\d+[smhd]$").unwrap());

    if !rule.is_match(timeout) {
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

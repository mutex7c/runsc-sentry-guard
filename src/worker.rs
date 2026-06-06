// Containment Mitigation Engine
// Invokes localized host sandboxing isolation techniques and direct socket interactions safely.

use crate::config::AtomicAction;
use crate::logger::emit_log;
use ipnet::IpNet;
use std::io::BufRead;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::IpAddr;

const WEBHOOK_TIMEOUT_SECS: u64 = 5;

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

#[cfg(target_os = "linux")]
fn read_bounded_line<R: std::io::BufRead>(reader: &mut R, limit: u64) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut buf)
        .map_err(|e| e.to_string())?;

    if buf.len() as u64 == limit && !buf.ends_with(&[b'\n']) {
        return Err("Buffer-bloat protection: HTTP line exceeded maximum bounded length".into());
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Zero-Fork Native HTTP Over Unix Domain Socket Engine (Linux Production Mode Only)
#[cfg(target_os = "linux")]
fn execute_docker_uds_request(
    method: &str,
    path: &str,
    body: Option<&str>,
    socket_path: &str,
) -> Result<(u16, String), String> {
    use std::io::{BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    // FIX: Client connects dynamically to the path passed from configuration routing
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!(
            "Container Engine Socket Connection Refused at {}: {}",
            socket_path, e
        )
    })?;

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let request_payload = if let Some(b) = body {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            method,
            path,
            b.len(),
            b
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            method, path
        )
    };

    stream
        .write_all(request_payload.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);

    let status_line = read_bounded_line(&mut reader, 8192)?;

    if status_line.is_empty() {
        return Err("Received completely empty frame stream from container daemon socket.".into());
    }

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(500);

    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;

    loop {
        let line = read_bounded_line(&mut reader, 8192)?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            break;
        }

        let lower_line = trimmed.to_lowercase();
        if lower_line.starts_with("transfer-encoding:") && lower_line.contains("chunked") {
            is_chunked = true;
        }
        if lower_line.starts_with("content-length:") {
            let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
            if parts.len() == 2 {
                content_length = parts[1].trim().parse::<usize>().ok();
            }
        }
    }

    let mut body_payload = String::new();

    if is_chunked {
        loop {
            let chunk_size_str = read_bounded_line(&mut reader, 8192)?;

            let trimmed_size = chunk_size_str.split(';').next().unwrap_or("").trim();
            if trimmed_size.is_empty() {
                continue;
            }

            let chunk_size = usize::from_str_radix(trimmed_size, 16)
                .map_err(|e| format!("Failed to parse chunk size: {}", e))?;

            if chunk_size == 0 {
                break;
            }

            let mut chunk_buf = vec![0; chunk_size];
            reader
                .read_exact(&mut chunk_buf)
                .map_err(|e| e.to_string())?;
            body_payload.push_str(&String::from_utf8_lossy(&chunk_buf));

            let mut crlf = vec![0; 2];
            let _ = reader.read_exact(&mut crlf);
        }
    } else if let Some(len) = content_length {
        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        body_payload = String::from_utf8_lossy(&buf).into_owned();
    } else {
        reader
            .take(65536)
            .read_to_string(&mut body_payload)
            .map_err(|e| e.to_string())?;
    }

    Ok((status_code, body_payload))
}

fn webhook_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(WEBHOOK_TIMEOUT_SECS)))
            .build()
            .into()
    })
}

fn build_webhook_payload(container_id: &str) -> String {
    serde_json::json!({
        "text": format!(
            "🚨 [SENTRY-GUARD] Active containment pipeline triggered for container context: {}",
            container_id
        )
    })
    .to_string()
}

fn dispatch_webhook_alert(url: &str, container_id: &str) -> Result<(), String> {
    let payload = build_webhook_payload(container_id);

    let response = webhook_agent()
        .post(url)
        .content_type("application/json")
        .send(payload.as_str())
        .map_err(|e| match e {
            ureq::Error::StatusCode(code) => {
                format!("Webhook dispatch rejected by endpoint (HTTP {}).", code)
            }
            ureq::Error::BadUri(uri) => format!("Webhook URL rejected as invalid: {}", uri),
            ureq::Error::HostNotFound => "Webhook host resolution failed.".to_string(),
            ureq::Error::Timeout(_) => format!(
                "Webhook dispatch exceeded {}-second execution boundary.",
                WEBHOOK_TIMEOUT_SECS
            ),
            other => format!("Webhook dispatch failed: {}", other),
        })?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Webhook dispatch rejected by endpoint (HTTP {}).",
            response.status().as_u16()
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn is_ip_safe(target_ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    whitelist.iter().any(|network| network.contains(target_ip))
}

#[cfg(target_os = "linux")]
pub fn resolve_container_ips(
    container_id: &str,
    json_enabled: bool,
    socket_path: &str,
) -> Vec<IpAddr> {
    let endpoint = format!("/containers/{}/json", container_id);
    let mut ips = Vec::new();

    match execute_docker_uds_request("GET", &endpoint, None, socket_path) {
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
                    "Container socket returned HTTP {} during IP resolution.",
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
                    "Failed to query Container socket for networking metadata via UDS channel: {}",
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
    socket_path: &str,
    trigger_message: &str,
) -> Result<(), String> {
    let _ = whitelist;
    let _ = socket_path;

    match action {
        AtomicAction::WebhookAlert { url } => dispatch_webhook_alert(url, container_id),

        AtomicAction::RunCustomScript { path } => {
            #[cfg(target_os = "linux")]
            let resolved_ip = {
                let ips = resolve_container_ips(container_id, json_enabled, socket_path);
                if ips.is_empty() {
                    "UNKNOWN_IP".to_string()
                } else {
                    ips.iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                }
            };

            #[cfg(not(target_os = "linux"))]
            let resolved_ip = "127.0.0.1".to_string();

            let mut child = Command::new(path)
                .arg(container_id)
                .arg(&resolved_ip)
                .arg(trigger_message)
                .spawn()
                .map_err(|e| format!("Failed to spawn automation extension subprocess: {}", e))?;

            let timeout = std::time::Duration::from_secs(15);
            let start = std::time::Instant::now();

            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return if status.success() {
                            Ok(())
                        } else {
                            Err(format!(
                                "Custom extension script exited with failure footprint: {}",
                                status
                            ))
                        };
                    }
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err("Custom extension script exceeded 15-second execution boundary. Process forcefully terminated.".into());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => {
                        return Err(format!("Failed to parse child execution status: {}", e));
                    }
                }
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
                        let endpoint = format!("/containers/{}/json", container_id);
                        let (status, json_payload) =
                            execute_docker_uds_request("GET", &endpoint, None, socket_path)?;

                        if status == 200 {
                            // Verify the container is actually still running, not just dead/exited
                            if json_payload.contains("\"Running\": true")
                                || json_payload.contains("\"Running\":true")
                            {
                                emit_log(
                                    "INFO",
                                    "worker_engine",
                                    None,
                                    Some(container_id),
                                    None,
                                    Some("validate_state"),
                                    "SUCCESS",
                                    "Container state verified as active. Proceeding with containment pipeline.",
                                    json_enabled,
                                );
                                Ok(())
                            } else {
                                Err("Container is no longer in a running state. Aborting containment to prevent TOCTOU misfires.".into())
                            }
                        } else {
                            Err(format!(
                                "State validation rejected (HTTP {}). Container likely terminated.",
                                status
                            ))
                        }
                    }

                    AtomicAction::Pause => {
                        let endpoint = format!("/containers/{}/pause", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None, socket_path)?;

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
                            execute_docker_uds_request("POST", &endpoint, None, socket_path)?;

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
                            execute_docker_uds_request("POST", &endpoint, None, socket_path)?;

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
                            execute_docker_uds_request("POST", &query_path, None, socket_path)?;

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
                            execute_docker_uds_request("POST", &query_path, None, socket_path)?;

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
                        let ips = resolve_container_ips(container_id, json_enabled, socket_path);

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
    socket_path: String,
    trigger_message: String,
) {
    let mut pipeline_failed = false;

    for action in &try_actions {
        if let Err(e) = execute_atomic_command(
            action,
            &container_id,
            &whitelist,
            &table,
            json_enabled,
            &socket_path,
            &trigger_message,
        ) {
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
            if let Err(fallback_error) = execute_atomic_command(
                fallback,
                &container_id,
                &whitelist,
                &table,
                json_enabled,
                &socket_path,
                &trigger_message,
            ) {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::thread;

    fn read_http_request(mut stream: TcpStream, response_status: &'static str) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        let mut content_length = 0usize;

        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line).unwrap();
            if bytes_read == 0 {
                break;
            }

            if line.to_ascii_lowercase().starts_with("content-length:")
                && let Some((_, value)) = line.split_once(':')
            {
                content_length = value.trim().parse().unwrap();
            }

            request.push_str(&line);

            if line == "\r\n" {
                break;
            }
        }

        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
        }

        let response = format!(
            "HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            response_status
        );
        stream.write_all(response.as_bytes()).unwrap();
        request
    }

    fn spawn_webhook_server(response_status: &'static str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/alert", listener.local_addr().unwrap());

        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            read_http_request(stream, response_status)
        });

        (url, handle)
    }

    #[test]
    fn test_is_ip_safe_evaluations() {
        let whitelist = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
        ];

        let safe_ip: IpAddr = "10.5.5.5".parse().unwrap();
        let unsafe_ip: IpAddr = "172.16.0.5".parse().unwrap();

        assert!(
            is_ip_safe(&safe_ip, &whitelist),
            "Failed: 10.5.5.5 should be whitelisted"
        );
        assert!(
            !is_ip_safe(&unsafe_ip, &whitelist),
            "Failed: 172.16.0.5 should be blacklisted"
        );
    }

    #[test]
    fn test_read_bounded_line_success() {
        let data = b"HTTP/1.1 200 OK\r\n";
        let mut cursor = Cursor::new(data);

        let result = read_bounded_line(&mut cursor, 1024).unwrap();
        assert_eq!(result, "HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn test_read_bounded_line_bloat_protection() {
        let data = vec![b'A'; 100];
        let mut cursor = Cursor::new(data);

        let result = read_bounded_line(&mut cursor, 50);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Buffer-bloat protection: HTTP line exceeded maximum bounded length"
        );
    }

    #[test]
    fn test_webhook_payload_is_valid_json() {
        let payload = build_webhook_payload("abcdef123456");
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            parsed["text"].as_str().unwrap(),
            "🚨 [SENTRY-GUARD] Active containment pipeline triggered for container context: abcdef123456"
        );
    }

    #[test]
    fn test_webhook_alert_dispatches_native_json_post() {
        let (url, handle) = spawn_webhook_server("204 No Content");
        let action = AtomicAction::WebhookAlert { url };
        let whitelist: Vec<IpNet> = Vec::new();

        let result = execute_atomic_command(
            &action,
            "abcdef123456",
            &whitelist,
            "inet security_ops",
            false,
            "/tmp/no-container-socket",
            "trigger",
        );

        assert!(result.is_ok(), "webhook dispatch failed: {:?}", result);

        let request = handle.join().unwrap();
        let lower_request = request.to_ascii_lowercase();

        assert!(request.starts_with("POST /alert HTTP/1.1"));
        assert!(lower_request.contains("content-type: application/json"));

        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            parsed["text"].as_str().unwrap(),
            "🚨 [SENTRY-GUARD] Active containment pipeline triggered for container context: abcdef123456"
        );
    }

    #[test]
    fn test_webhook_alert_reports_http_failure() {
        let (url, handle) = spawn_webhook_server("500 Internal Server Error");
        let action = AtomicAction::WebhookAlert { url };
        let whitelist: Vec<IpNet> = Vec::new();

        let error = execute_atomic_command(
            &action,
            "abcdef123456",
            &whitelist,
            "inet security_ops",
            false,
            "/tmp/no-container-socket",
            "trigger",
        )
        .unwrap_err();

        assert_eq!(error, "Webhook dispatch rejected by endpoint (HTTP 500).");
        let _ = handle.join().unwrap();
    }
}

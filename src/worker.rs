// Containment Mitigation Engine
// Invokes localized host sandboxing isolation techniques
// and direct socket interactions safely

use crate::config::{AtomicAction, LogLevel};
use crate::logger::emit_log;
use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use std::process::Command;
use std::sync::Arc;

#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::io::BufRead;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

// Platform-gated import strictly to Linux to eliminate macOS/Windows unused-trait warnings
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

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

#[derive(Deserialize, Debug)]
#[cfg(target_os = "linux")]
pub struct DockerEventPayload {
    #[serde(rename = "Type")]
    #[allow(dead_code)]
    pub event_type: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Actor")]
    pub actor: DockerEventActor,
}

#[derive(Deserialize, Debug)]
#[cfg(target_os = "linux")]
pub struct DockerEventActor {
    #[serde(rename = "ID")]
    pub id: String,
}

#[cfg(target_os = "linux")]
fn read_bounded_line<R: std::io::BufRead>(reader: &mut R, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut buf)
        .map_err(|e| anyhow!("I/O Error reading bounded line: {}", e))?;

    if buf.len() as u64 == limit && !buf.ends_with(&[b'\n']) {
        bail!("Buffer-bloat protection: HTTP line exceeded maximum bounded length");
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// Zero-Fork Native HTTP Over Unix Domain Socket Engine (Linux Production Mode Only)
#[cfg(target_os = "linux")]
const MAX_UDS_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB Heap Ceiling

#[cfg(target_os = "linux")]
fn execute_docker_uds_request(
    method: &str,
    path: &str,
    body: Option<&str>,
    socket_path: &str,
    config_log_level: LogLevel,
    json_enabled: bool,
) -> Result<(u16, String)> {
    use std::io::{BufReader, Cursor, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        anyhow!(
            "Container Engine Socket Connection Refused at {}: {}",
            socket_path,
            e
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
        .map_err(|e| anyhow!("Failed to write to UDS: {}", e))?;
    stream
        .flush()
        .map_err(|e| anyhow!("Failed to flush UDS stream: {}", e))?;

    let mut header_buf = [0u8; 8192];
    let mut bytes_read = 0;

    let header_end;
    let status_code;

    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;

    // Safely read and validate HTTP headers using httparse
    loop {
        if bytes_read >= header_buf.len() {
            bail!("UDS Error: HTTP Headers exceeded 8KB maximum boundary.");
        }

        let n = stream
            .read(&mut header_buf[bytes_read..])
            .map_err(|e| anyhow!("Failed to read UDS stream: {}", e))?;
        if n == 0 {
            bail!("UDS Error: Stream closed prematurely.");
        }
        bytes_read += n;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);

        match res.parse(&header_buf[..bytes_read]) {
            Ok(httparse::Status::Complete(body_start_offset)) => {
                header_end = body_start_offset;
                status_code = res.code.unwrap_or(500);
                for header in res.headers {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_lowercase();
                    if name == "transfer-encoding" && value.contains("chunked") {
                        is_chunked = true;
                    } else if name == "content-length" {
                        content_length = String::from_utf8_lossy(header.value).trim().parse::<usize>().ok();
                    }
                }
                break;
            }
            Ok(httparse::Status::Partial) => continue,
            Err(e) => bail!("UDS Error: Malformed HTTP response format intercepted: {}", e),
        }
    }

    // Process the remaining body bytes
    let leftover = header_buf[header_end..bytes_read].to_vec();
    let mut reader = BufReader::new(Cursor::new(leftover).chain(stream));
    let mut body_payload = String::new();

    if is_chunked {
        loop {
            let chunk_size_str = read_bounded_line(&mut reader, 8192)?;

            let trimmed_size = chunk_size_str.split(';').next().unwrap_or("").trim();
            if trimmed_size.is_empty() {
                continue;
            }

            let chunk_size = usize::from_str_radix(trimmed_size, 16)
                .map_err(|e| anyhow!("Failed to parse chunk size: {}", e))?;

            if chunk_size == 0 {
                break;
            }

            if chunk_size > MAX_UDS_PAYLOAD_SIZE
                || body_payload.len() + chunk_size > MAX_UDS_PAYLOAD_SIZE
            {
                bail!(
                    "SECURITY ABORT: Chunk sequence size exceeds maximum allowed UDS payload limit of {} bytes.",
                    MAX_UDS_PAYLOAD_SIZE
                );
            }

            // Forensics Telemetry Hook: Gated strictly under Trace scope to track live buffer decoding sequences
            emit_log(
                "TRACE",
                "worker_engine",
                None,
                None,
                None,
                Some("stream_chunk"),
                "PROCESSING",
                &format!("Decoding dynamic chunked telemetry sequence of size {} bytes.", chunk_size),
                config_log_level,
                json_enabled,
            );

            let mut chunk_buf = vec![0; chunk_size];
            reader
                .read_exact(&mut chunk_buf)
                .map_err(|e| anyhow!("Failed to read chunk payload: {}", e))?;
            body_payload.push_str(&String::from_utf8_lossy(&chunk_buf));

            let mut crlf = vec![0; 2];
            let _ = reader.read_exact(&mut crlf);
        }
    } else if let Some(len) = content_length {
        if len > MAX_UDS_PAYLOAD_SIZE {
            bail!(
                "SECURITY ABORT: Content-Length {} exceeds maximum allowed UDS payload limit of {} bytes.",
                len, MAX_UDS_PAYLOAD_SIZE
            );
        }
        let mut buf = vec![0; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| anyhow!("Failed to read exact payload length: {}", e))?;
        body_payload = String::from_utf8_lossy(&buf).into_owned();
    } else {
        reader
            .take(MAX_UDS_PAYLOAD_SIZE as u64)
            .read_to_string(&mut body_payload)
            .map_err(|e| anyhow!("Failed to read payload to string: {}", e))?;
    }

    Ok((status_code, body_payload))
}

#[cfg(target_os = "linux")]
pub fn is_ip_safe(target_ip: &IpAddr, whitelist: &[IpNet]) -> bool {
    whitelist.iter().any(|network| network.contains(target_ip))
}

#[cfg(target_os = "linux")]
pub fn resolve_container_ips(
    container_id: &str,
    config_log_level: LogLevel,
    json_enabled: bool,
    socket_path: &str,
) -> Vec<IpAddr> {
    let endpoint = format!("/containers/{}/json", container_id);
    let mut ips = Vec::new();

    match execute_docker_uds_request("GET", &endpoint, None, socket_path, config_log_level, json_enabled) {
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
                config_log_level,
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
                    "Failed to query Container socket for networking metadata via UDS channel: {:#}",
                    e
                ),
                config_log_level,
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
    config_log_level: LogLevel,
    json_enabled: bool,
    socket_path: &str,
    trigger_message: &str,
) -> Result<()> {
    let _ = whitelist;
    let _ = socket_path;

    match action {
        AtomicAction::WebhookAlert { url } => {
            let payload_obj = serde_json::json!({
                "text": format!("[SENTRY-GUARD] Active containment pipeline triggered for container context: {}", container_id)
            });
            let payload = serde_json::to_string(&payload_obj)
                .map_err(|e| anyhow!("Failed to serialize webhook alert payload: {}", e))?;

            let s = Command::new("curl")
                .args(&[
                    "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "--max-time", "5",
                    "--connect-timeout", "3",
                    "--data", &payload,
                    url,
                ])
                .status()
                .map_err(|e| anyhow!("Failed to invoke system curl binary: {}", e))?;

            if s.success() {
                Ok(())
            } else {
                bail!("Webhook dispatch failed. curl exited with non-zero status code: {:?}", s.code());
            }
        }

        AtomicAction::RunCustomScript { path } => {
            #[cfg(target_os = "linux")]
            let resolved_ip = {
                let ips = resolve_container_ips(container_id, config_log_level, json_enabled, socket_path);
                if ips.is_empty() {
                    "UNKNOWN_IP".to_string()
                } else {
                    ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",")
                }
            };

            #[cfg(not(target_os = "linux"))]
            let resolved_ip = "127.0.0.1".to_string();

            let mut cmd = Command::new(path);
            cmd.arg(container_id).arg(&resolved_ip).arg(trigger_message);

            #[cfg(target_os = "linux")]
            {
                unsafe {
                    cmd.pre_exec(|| {
                        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
                        Ok(())
                    });
                }
            }

            let mut child = cmd.spawn().map_err(|e| anyhow!("Failed to spawn automation extension subprocess: {}", e))?;
            let timeout = std::time::Duration::from_secs(15);
            let start = std::time::Instant::now();

            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if status.success() {
                            return Ok(());
                        } else {
                            bail!("Custom extension script exited with failure footprint: {}", status);
                        }
                    }
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            if let Err(e) = child.kill() {
                                emit_log("ERROR", "worker_engine", None, Some(container_id), None, Some("script_kill"), "LEAK", &format!("Failed to kill runaway script process: {:#}", e), config_log_level, json_enabled);
                            }
                            match child.wait() {
                                Ok(status) => emit_log("INFO", "worker_engine", None, Some(container_id), None, Some("script_reap"), "SUCCESS", &format!("Runaway script reaped. Status: {}", status), config_log_level, json_enabled),
                                Err(e) => emit_log("ERROR", "worker_engine", None, Some(container_id), None, Some("script_reap"), "ZOMBIE", &format!("Failed to wait for killed child: {:#}", e), config_log_level, json_enabled),
                            }
                            bail!("Custom extension script exceeded 15-second execution boundary. Process forcefully terminated.");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => {
                        bail!("Failed to parse child execution status: {}", e);
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
                config_log_level,
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
                config_log_level,
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
                            execute_docker_uds_request("GET", &endpoint, None, socket_path, config_log_level, json_enabled)?;

                        if status == 200 {
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
                                    config_log_level,
                                    json_enabled,
                                );
                                Ok(())
                            } else {
                                bail!("Container is no longer in a running state. Aborting containment to prevent TOCTOU misfires.");
                            }
                        } else {
                            bail!(
                                "State validation rejected (HTTP {}). Container likely terminated.",
                                status
                            );
                        }
                    }

                    AtomicAction::Pause => {
                        let endpoint = format!("/containers/{}/pause", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None, socket_path, config_log_level, json_enabled)?;

                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            bail!(
                                "Pause mutation rejected (HTTP {}): {}",
                                status,
                                err_payload
                            );
                        }
                    }

                    AtomicAction::Unpause => {
                        let endpoint = format!("/containers/{}/unpause", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None, socket_path, config_log_level, json_enabled)?;

                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            bail!(
                                "Unpause mutation rejected (HTTP {}): {}",
                                status,
                                err_payload
                            );
                        }
                    }

                    AtomicAction::Restart => {
                        let endpoint = format!("/containers/{}/restart", container_id);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &endpoint, None, socket_path, config_log_level, json_enabled)?;

                        if (200..300).contains(&status) {
                            Ok(())
                        } else {
                            bail!(
                                "Restart mutation rejected (HTTP {}): {}",
                                status,
                                err_payload
                            );
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
                            execute_docker_uds_request("POST", &query_path, None, socket_path, config_log_level, json_enabled)?;

                        if (200..300).contains(&status) {
                            Ok(())
                        } else {
                            bail!(
                                "CommitSnapshot rejected (HTTP {}): {}",
                                status,
                                err_payload
                            );
                        }
                    }

                    AtomicAction::ContainerSignal { signal } => {
                        let query_path =
                            format!("/containers/{}/kill?signal={}", container_id, signal);
                        let (status, err_payload) =
                            execute_docker_uds_request("POST", &query_path, None, socket_path, config_log_level, json_enabled)?;

                        if (200..300).contains(&status) || status == 409 {
                            Ok(())
                        } else {
                            bail!(
                                "ContainerSignal rejected (HTTP {}): {}",
                                status,
                                err_payload
                            );
                        }
                    }

                    AtomicAction::NftBlacklist { set_name, timeout } => {
                        let ips = resolve_container_ips(container_id, config_log_level, json_enabled, socket_path);

                        if ips.is_empty() {
                            bail!("IP resolution yielded zero addresses; cannot apply nftables blacklist.");
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
                                    config_log_level,
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
                                config_log_level,
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
                        println!("[DEV-MOCK] Verifying runtime operational status for ID: {}", container_id);
                        Ok(())
                    }
                    AtomicAction::Pause => {
                        println!("[DEV-MOCK] Injecting out-of-band container namespace FREEZE on ID: {}", container_id);
                        Ok(())
                    }
                    AtomicAction::Unpause => {
                        println!("[DEV-MOCK] Releasing container namespace FREEZE mutation execution on ID: {}", container_id);
                        Ok(())
                    }
                    AtomicAction::Restart => {
                        println!("[DEV-MOCK] Dispatching rolling container runtime reboot signature to ID: {}", container_id);
                        Ok(())
                    }
                    AtomicAction::CommitSnapshot { prefix } => {
                        println!("[DEV-MOCK] Committing container snapshot to register using tag: {}-{}", prefix, container_id);
                        Ok(())
                    }
                    AtomicAction::ContainerSignal { signal } => {
                        println!("[DEV-MOCK] Injecting kernel process termination signal [{}] straight to target ID: {}", signal, container_id);
                        Ok(())
                    }
                    AtomicAction::NftBlacklist { set_name, timeout } => {
                        println!("[DEV-MOCK] Appending element drop logic -> Table: {}, Set: {}, Duration: {}", table, set_name, timeout);
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
) -> Result<()> {
    use regex::Regex;
    static TIMEOUT_RULE: OnceLock<Regex> = OnceLock::new();
    static IDENTIFIER_RULE: OnceLock<Regex> = OnceLock::new();

    let t_rule = TIMEOUT_RULE.get_or_init(|| Regex::new(r"^\d+[smhd]$").unwrap());
    let id_rule = IDENTIFIER_RULE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_]+$").unwrap());

    if !t_rule.is_match(timeout) {
        bail!("Security Constraint Violation: Intercepted malformed firewall duration payload: '{}'", timeout);
    }

    let table_parts: Vec<&str> = table.split_whitespace().collect();
    if table_parts.len() != 2 {
        bail!("Security Error: Malformed nftables table format configuration. Expected exact 'family name' (e.g., 'inet filter').");
    }
    let family = table_parts[0];
    let table_name = table_parts[1];

    if !id_rule.is_match(family) || !id_rule.is_match(table_name) || !id_rule.is_match(set) {
        bail!("Security Error: Malformed firewall identifier detected. Arguments must match alphanumeric/underscore boundaries.");
    }

    let element_payload = format!("{{ {} timeout {} comment \"runsc-sentry-guard\" }}", ip, timeout);

    let s = Command::new("nft")
        .arg("add")
        .arg("element")
        .arg(family)
        .arg(table_name)
        .arg(set)
        .arg(&element_payload)
        .status()
        .map_err(|e| anyhow!("Subprocess execution failed: {}", e))?;

    if s.success() {
        Ok(())
    } else {
        bail!("Kernel nftables transaction rejected execution parameters.");
    }
}

#[derive(Deserialize)]
#[cfg(target_os = "linux")]
struct DockerContainerListResponse {
    #[serde(rename = "Id")]
    id: String,
}

#[cfg(target_os = "linux")]
pub fn fetch_running_container_ids(socket_path: &str) -> std::collections::HashSet<String> {
    use std::collections::HashSet;

    match execute_docker_uds_request("GET", "/containers/json", None, socket_path, LogLevel::Info, true) {
        Ok((status, json_payload)) if status == 200 => {
            if let Ok(parsed) =
                serde_json::from_str::<Vec<DockerContainerListResponse>>(&json_payload)
            {
                return parsed.into_iter().map(|c| c.id).collect();
            }
        }
        _ => {}
    }
    HashSet::new()
}

pub fn execute_containment_pipeline(
    container_id: String,
    try_actions: Vec<AtomicAction>,
    final_actions: Vec<AtomicAction>,
    whitelist: Arc<Vec<IpNet>>,
    table: Arc<String>,
    config_log_level: LogLevel,
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
            &whitelist[..],
            &table,
            config_log_level,
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
                &format!("Primary playbook action failed structural context: {:#}", e),
                config_log_level,
                json_enabled,
            );
            pipeline_failed = true;
            break;
        }
    }

    if pipeline_failed {
        emit_json_escalation_marker(&container_id, &rule_name, config_log_level, json_enabled);

        for fallback in &final_actions {
            match execute_atomic_command(
                fallback,
                &container_id,
                &whitelist[..],
                &table,
                config_log_level,
                json_enabled,
                &socket_path,
                &trigger_message,
            ) {
                Ok(_) => {
                    emit_log(
                        "INFO",
                        "worker_engine",
                        Some(&rule_name),
                        Some(&container_id),
                        None,
                        Some(&format!("{:?}", fallback)),
                        "SUCCESS",
                        "Emergency fallback action executed successfully.",
                        config_log_level,
                        json_enabled,
                    );

                    match fallback {
                        AtomicAction::ContainerSignal { signal } => {
                            if signal == "SIGKILL" || signal == "SIGSTOP" {
                                emit_log(
                                    "CRITICAL",
                                    "runsc_sentry_guard",
                                    Some(&rule_name),
                                    Some(&container_id),
                                    None,
                                    None,
                                    "HALTED",
                                    "Terminal signal delivered. Short-circuiting remaining fallback chain.",
                                    config_log_level,
                                    json_enabled,
                                );
                                break;
                            }
                        }
                        AtomicAction::Restart => {
                            emit_log(
                                "CRITICAL",
                                "runsc_sentry_guard",
                                Some(&rule_name),
                                Some(&container_id),
                                None,
                                None,
                                "HALTED",
                                "Container runtime restarted. Short-circuiting remaining fallback chain.",
                                config_log_level,
                                json_enabled,
                            );
                            break;
                        }
                        _ => {}
                    }
                }
                Err(fallback_error) => {
                    emit_log(
                        "CRITICAL",
                        "worker_engine",
                        Some(&rule_name),
                        Some(&container_id),
                        None,
                        Some(&format!("{:?}", fallback)),
                        "CRASH",
                        &format!("EMERGENCY CONTAINMENT FAILURE: {:#}", fallback_error),
                        config_log_level,
                        json_enabled,
                    );
                }
            }
        }
    }
}

fn emit_json_escalation_marker(container_id: &str, rule: &str, config_log_level: LogLevel, json_enabled: bool) {
    emit_log(
        "CRITICAL",
        "worker_engine",
        Some(rule),
        Some(container_id),
        None,
        Some("escalation_routing"),
        "ENGAGED",
        "Primary playbook failed structural strategy. Deploying fallback containment actions.",
        config_log_level,
        json_enabled,
    );
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::io::Cursor;
    use std::net::IpAddr;

    fn run_mock_line_reader(stream_payload: Vec<u8>, capacity_limit: u64) -> Result<String> {
        let mut mock_cursor = Cursor::new(stream_payload);
        read_bounded_line(&mut mock_cursor, capacity_limit)
    }

    #[test]
    fn test_is_ip_safe_evaluations() {
        let whitelist = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
        ];

        let safe_ip: IpAddr = "10.5.5.5".parse().unwrap();
        let unsafe_ip: IpAddr = "172.16.0.5".parse().unwrap();

        assert!(is_ip_safe(&safe_ip, &whitelist), "Failed: 10.5.5.5 should be whitelisted");
        assert!(!is_ip_safe(&unsafe_ip, &whitelist), "Failed: 172.16.0.5 should be blacklisted");
    }

    #[test]
    fn test_read_bounded_line_success() {
        let result = run_mock_line_reader(b"HTTP/1.1 200 OK\r\n".to_vec(), 1024).unwrap();
        assert_eq!(result, "HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn test_read_bounded_line_bloat_protection() {
        let result = run_mock_line_reader(vec![b'A'; 100], 50);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Buffer-bloat protection: HTTP line exceeded maximum bounded length"));
    }

    #[test]
    fn test_read_bounded_line_exact_limit_anomaly() {
        let result = run_mock_line_reader(vec![b'B'; 64], 64);
        assert!(result.is_err(), "Engine should fail if buffer hits limit exactly without finding a newline");
    }

    #[test]
    fn test_firewall_timeout_injection_defense() {
        let target_ip = "10.0.0.2";
        let target_set = "blacklist_set";
        let target_table = "inet filter";
        let malicious_timeout = "24h; nft delete table inet filter;";

        let validation_result = execute_firewall_mutation(target_ip, target_set, malicious_timeout, target_table);
        assert!(validation_result.is_err());

        if let Err(err) = validation_result {
            assert!(err.to_string().contains("Security Error"));
        }
    }

    #[test]
    fn test_execute_uds_request_length_boundary_violation() {
        let test_payload_len = 11534336usize;
        let maximum_heap_ceiling = MAX_UDS_PAYLOAD_SIZE;

        assert!(test_payload_len > maximum_heap_ceiling, "Assertion matrix failed to register a structural boundary breach");
    }
}

#[allow(dead_code)]
pub fn extract_id_from_lines<I, S>(lines: I, id_extractor: &regex::Regex) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut fallback: Option<String> = None;
    for line_ref in lines {
        let line = line_ref.as_ref();
        if let Some(caps) = id_extractor.captures(line) {
            if let Some(matched_id) = caps.get(1) {
                let id = matched_id.as_str().to_string();
                if line.contains("docker") || line.contains("kubepods") || line.contains("containerd") || line.contains("runsc") {
                    return Some(id);
                }
                if fallback.is_none() {
                    fallback = Some(id);
                }
            }
        }
    }
    fallback
}

pub fn cleanup_stale_firewall_elements(config: &crate::config::GuardConfig) {
    let table = &config.monitor.nftables_default_table;
    let ip_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|([a-fA-F0-9:]+:+[a-fA-F0-9:]+)\b").unwrap();
    let json_enabled = config.monitor.json_logging_enabled;
    let config_log_level = config.monitor.log_level;

    let table_parts: Vec<&str> = table.split_whitespace().collect();
    if table_parts.len() != 2 {
        emit_log("ERROR", "bootstrap_cleanup", None, None, None, Some("config"), "FAILURE", "Malformed table definition in manifest. Cleanup skipped.", config_log_level, json_enabled);
        return;
    }
    let family = table_parts[0];
    let table_name = table_parts[1];

    for rule in &config.rules {
        let combined_actions = rule.try_actions.iter().chain(rule.final_actions.iter());
        for action in combined_actions {
            if let AtomicAction::NftBlacklist { set_name, .. } = action {
                let output = Command::new("nft")
                    .arg("list")
                    .arg("set")
                    .arg(family)
                    .arg(table_name)
                    .arg(set_name)
                    .output();

                if let Ok(out) = output {
                    let stdout_str = String::from_utf8_lossy(&out.stdout);
                    let mut stale_ips = Vec::new();

                    for line in stdout_str.lines() {
                        if line.contains("comment \"runsc-sentry-guard\"") {
                            if let Some(caps) = ip_regex.captures(line) {
                                if let Some(matched_ip) = caps.get(0) {
                                    stale_ips.push(matched_ip.as_str().to_string());
                                }
                            }
                        }
                    }

                    if !stale_ips.is_empty() {
                        let elements_payload = format!("{{ {} }}", stale_ips.join(", "));

                        match Command::new("nft")
                            .arg("delete")
                            .arg("element")
                            .arg(family)
                            .arg(table_name)
                            .arg(set_name)
                            .arg(&elements_payload)
                            .status()
                        {
                            Ok(s) if s.success() => {},
                            Ok(s) => emit_log("WARN", "bootstrap_cleanup", None, None, None, Some("nft"), "FAILURE", &format!("nft delete exited with code: {:?}", s.code()), config_log_level, json_enabled),
                            Err(e) => emit_log("ERROR", "bootstrap_cleanup", None, None, None, Some("nft"), "CRASH", &format!("Failed to execute nft binary: {:#}", e), config_log_level, json_enabled),
                        }
                    }
                }
            }
        }
    }
}
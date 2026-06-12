// Ingestion Pipeline Engine
// Operates high-performance file tailers and parallel UDS socket tracking pipelines cleanly.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::config::{AtomicAction, GuardConfig, IngestionMode};
use crate::logger::emit_log;
use crate::worker::execute_containment_pipeline;

struct LogDescriptor {
    inode: u64,
    position: u64,
}

// Added the trigger string to the worker channel message
type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String, String);
type RegistryMap = HashMap<String, SyncSender<WorkerChannelMessage>>;

pub fn start_monitor_loop(config: GuardConfig, shutdown_requested: Arc<AtomicBool>) {
    let mode = &config.monitor.mode;
    let json_enabled = config.monitor.json_logging_enabled;
    let whitelist = config.monitor.ip_whitelist.clone();
    let table = config.monitor.nftables_default_table.clone();
    let docker_socket_path = config.monitor.docker_socket_path.clone();
    let watchdog_interval = config.monitor.systemd_watchdog_interval_ms;

    // Spawn a dedicated, decoupled watchdog heartbeat thread
    if watchdog_interval > 0 {
        let watchdog_shutdown = Arc::clone(&shutdown_requested);
        thread::spawn(move || {
            while !watchdog_shutdown.load(Ordering::SeqCst) {
                notify_systemd_watchdog();
                sleep_until_shutdown(&watchdog_shutdown, Duration::from_millis(watchdog_interval));
            }
        });
    }

    let worker_registry: Arc<Mutex<RegistryMap>> = Arc::new(Mutex::new(HashMap::new()));
    let regex_compiled: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>> = Arc::new(
        config
            .rules
            .iter()
            .filter_map(|r| {
                Regex::new(&r.regex_match).ok().map(|compiled| {
                    (
                        r.name.clone(),
                        compiled,
                        r.try_actions.clone(),
                        r.final_actions.clone(),
                    )
                })
            })
            .collect(),
    );

    let id_extractor = Regex::new(r"--id=\b([a-fA-F0-9]{12}|[a-fA-F0-9]{64})\b").unwrap();
    let mut file_state_tracker: HashMap<String, LogDescriptor> = HashMap::new();
    let mut first_run = true;
    let mut uds_thread = None;

    if mode == &IngestionMode::Socket || mode == &IngestionMode::Dual {
        let uds_registry = Arc::clone(&worker_registry);
        let uds_regex = Arc::clone(&regex_compiled);
        let uds_id_extractor = id_extractor.clone();
        let uds_whitelist = whitelist.clone();
        let uds_table = table.clone();
        let uds_socket_path = docker_socket_path.clone();
        let uds_shutdown = Arc::clone(&shutdown_requested);

        uds_thread = Some(thread::spawn(move || {
            run_uds_server(
                uds_registry,
                uds_regex,
                uds_id_extractor,
                uds_whitelist,
                uds_table,
                json_enabled,
                uds_socket_path,
                uds_shutdown,
            );
        }));
    }

    if mode == &IngestionMode::Socket {
        emit_log(
            "INFO",
            "orchestrator",
            None,
            None,
            None,
            None,
            "STARTED",
            "Out-of-band UDS streaming receiver active. Filesystem parsing idle.",
            json_enabled,
        );
        while !shutdown_requested.load(Ordering::SeqCst) {
            thread::park_timeout(Duration::from_millis(100));
        }

        if let Some(handle) = uds_thread {
            let _ = handle.join();
        }
        return;
    }

    emit_log(
        "INFO",
        "orchestrator",
        None,
        None,
        None,
        None,
        "STARTED",
        "Master directory tailer and Unix socket pipelines active.",
        json_enabled,
    );

    let mut scratchpad_buffer = Vec::with_capacity(8192);

    if mode == &IngestionMode::File {
        notify_systemd_ready();
    }

    while !shutdown_requested.load(Ordering::SeqCst) {
        let log_dir_path = Path::new(&config.monitor.log_dir);

        if !log_dir_path.exists() {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = fs::create_dir_all(log_dir_path);
            }
            #[cfg(target_os = "linux")]
            {
                emit_log(
                    "ERROR",
                    "orchestrator",
                    None,
                    None,
                    None,
                    None,
                    "MISSING",
                    "Target directory unreachable.",
                    json_enabled,
                );
                sleep_until_shutdown(
                    &shutdown_requested,
                    Duration::from_millis(config.monitor.check_interval_ms),
                );
                continue;
            }
        }

        // File Spoofing Mitigation: Strict Directory Ownership & Permission Audit
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(metadata) = log_dir_path.metadata() {
                // Ensure UID 0 (root) ownership and block world-writable (0o002) access
                if metadata.uid() != 0 || (metadata.mode() & 0o002) != 0 {
                    emit_log(
                        "CRITICAL",
                        "orchestrator",
                        None,
                        None,
                        None,
                        Some("directory_audit"),
                        "HALTED",
                        "Log directory is not owned by root or is world-writable. File mode suspended to prevent spoofing.",
                        json_enabled,
                    );
                    sleep_until_shutdown(
                        &shutdown_requested,
                        Duration::from_millis(config.monitor.check_interval_ms),
                    );
                    continue;
                }
            }
        }

        let mut actively_seen_paths = HashSet::new();

        if let Ok(entries) = fs::read_dir(log_dir_path) {
            for entry in entries.flatten() {
                if shutdown_requested.load(Ordering::SeqCst) {
                    break;
                }

                let path = entry.path();

                if path.extension().map_or(false, |ext| ext == "boot") {
                    let path_str = path.to_string_lossy().into_owned();
                    actively_seen_paths.insert(path_str.clone());

                    #[cfg(target_os = "linux")]
                    let current_inode = {
                        use std::os::linux::fs::MetadataExt;
                        path.metadata().map(|m| m.st_ino()).unwrap_or(0)
                    };

                    #[cfg(not(target_os = "linux"))]
                    let current_inode = 0;

                    if first_run {
                        if let Ok(metadata) = path.metadata() {
                            file_state_tracker.insert(
                                path_str.clone(),
                                LogDescriptor {
                                    inode: current_inode,
                                    position: metadata.len(),
                                },
                            );
                        }
                        continue;
                    }

                    let mut last_pos = 0;
                    if let Some(desc) = file_state_tracker.get(&path_str) {
                        if desc.inode == current_inode {
                            last_pos = desc.position;
                        }
                    }

                    #[cfg(unix)]
                    let file_result = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path);

                    #[cfg(not(unix))]
                    let file_result = fs::File::open(&path);

                    if let Ok(file) = file_result {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if let Ok(metadata) = file.metadata() {
                                if metadata.uid() != 0 {
                                    continue;
                                }
                            }
                        }

                        let mut reader = BufReader::new(file);

                        if let Err(e) = reader.seek(SeekFrom::Start(last_pos)) {
                            emit_log(
                                "ERROR",
                                "orchestrator",
                                None,
                                None,
                                None,
                                Some("seek"),
                                "FAILURE",
                                &format!("Failed to seek to target stream pointer: {}", e),
                                json_enabled,
                            );
                            continue;
                        }

                        loop {
                            if shutdown_requested.load(Ordering::SeqCst) {
                                break;
                            }

                            scratchpad_buffer.clear();
                            let mut reached_eof = false;
                            let mut exceeded_limit = false;

                            loop {
                                if shutdown_requested.load(Ordering::SeqCst) {
                                    reached_eof = true;
                                    break;
                                }

                                let available_buffer = match reader.fill_buf() {
                                    Ok(buf) if buf.is_empty() => {
                                        reached_eof = true;
                                        break;
                                    }
                                    Ok(buf) => buf,
                                    Err(_) => {
                                        reached_eof = true;
                                        break;
                                    }
                                };

                                if let Some(newline_pos) =
                                    available_buffer.iter().position(|&b| b == b'\n')
                                {
                                    let consume_len = newline_pos + 1;

                                    if scratchpad_buffer.len() + consume_len > 8192 {
                                        exceeded_limit = true;
                                        let allowed = 8192 - scratchpad_buffer.len();
                                        scratchpad_buffer
                                            .extend_from_slice(&available_buffer[..allowed]);
                                        reader.consume(allowed);
                                    } else {
                                        scratchpad_buffer
                                            .extend_from_slice(&available_buffer[..consume_len]);
                                        reader.consume(consume_len);
                                    }
                                    break;
                                } else {
                                    let chunk_len = available_buffer.len();

                                    if scratchpad_buffer.len() + chunk_len > 8192 {
                                        exceeded_limit = true;
                                        let allowed = 8192 - scratchpad_buffer.len();
                                        scratchpad_buffer
                                            .extend_from_slice(&available_buffer[..allowed]);
                                        reader.consume(allowed);
                                        break;
                                    } else {
                                        scratchpad_buffer.extend_from_slice(available_buffer);
                                        reader.consume(chunk_len);
                                    }
                                }
                            }

                            if reached_eof && scratchpad_buffer.is_empty() {
                                break;
                            }

                            let current_line = String::from_utf8_lossy(&scratchpad_buffer);
                            let trimmed_line = current_line.trim_end();

                            if exceeded_limit {
                                emit_log(
                                    "CRITICAL",
                                    "orchestrator",
                                    None,
                                    None,
                                    None,
                                    Some("stream"),
                                    "TRUNCATED",
                                    "Line limit hit. Payload ignored and remainder discarded to prevent sensor blinding.",
                                    json_enabled,
                                );
                                let mut discard = Vec::new();
                                let _ = reader.read_until(b'\n', &mut discard);
                                continue;
                            }

                            evaluate_line_signatures(
                                trimmed_line,
                                &regex_compiled,
                                &id_extractor,
                                &worker_registry,
                                &whitelist,
                                &table,
                                json_enabled,
                                &docker_socket_path,
                                true,
                            );
                        }

                        if let Ok(pos) = reader.stream_position() {
                            file_state_tracker.insert(
                                path_str,
                                LogDescriptor {
                                    inode: current_inode,
                                    position: pos,
                                },
                            );
                        }
                    }
                }
            }
        }

        file_state_tracker.retain(|path_key, _| actively_seen_paths.contains(path_key));
        first_run = false;
        sleep_until_shutdown(
            &shutdown_requested,
            Duration::from_millis(config.monitor.check_interval_ms),
        );
    }

    if let Some(handle) = uds_thread {
        let _ = handle.join();
    }
}

fn run_uds_server(
    registry: Arc<Mutex<RegistryMap>>,
    regex_rules: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>,
    id_extractor: Regex,
    whitelist: Vec<ipnet::IpNet>,
    table: String,
    json_enabled: bool,
    docker_socket_path: String,
    shutdown_requested: Arc<AtomicBool>,
) {
    let socket_path = "/var/run/runsc-sentry-guard.sock";
    let _ = fs::remove_file(socket_path);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            emit_log(
                "ERROR",
                "uds_server",
                None,
                None,
                None,
                None,
                "CRASH",
                &format!("UDS bind failed: {}", e),
                json_enabled,
            );
            return;
        }
    };

    if let Err(e) = listener.set_nonblocking(true) {
        emit_log(
            "ERROR",
            "uds_server",
            None,
            None,
            None,
            Some("nonblocking"),
            "CRASH",
            &format!(
                "Failed to configure UDS listener for graceful shutdown: {}",
                e
            ),
            json_enabled,
        );
        let _ = fs::remove_file(socket_path);
        return;
    }

    if let Err(e) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660)) {
        emit_log(
            "ERROR",
            "uds_server",
            None,
            None,
            None,
            Some("permissions"),
            "CRASH",
            &format!(
                "Failed to enforce secure access permissions on UDS socket: {}",
                e
            ),
            json_enabled,
        );
        return;
    }

    // The UDS socket is securely bound and ready for traffic
    notify_systemd_ready();

    // Prevent Unbounded OS Thread Creation DoS
    let active_connections = Arc::new(AtomicUsize::new(0));
    const MAX_UDS_CONNECTIONS: usize = 50;

    while !shutdown_requested.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if active_connections.load(Ordering::SeqCst) >= MAX_UDS_CONNECTIONS {
                    continue;
                }

                active_connections.fetch_add(1, Ordering::SeqCst);
                let conn_tracker = Arc::clone(&active_connections);

                let reg_clone = Arc::clone(&registry);
                let rules_clone = Arc::clone(&regex_rules);
                let id_clone = id_extractor.clone();
                let wl_clone = whitelist.clone();
                let tbl_clone = table.clone();
                let ds_path_clone = docker_socket_path.clone();
                let stream_shutdown = Arc::clone(&shutdown_requested);

                thread::spawn(move || {
                    handle_uds_stream(
                        stream,
                        reg_clone,
                        rules_clone,
                        id_clone,
                        wl_clone,
                        tbl_clone,
                        json_enabled,
                        ds_path_clone,
                        stream_shutdown,
                    );
                    conn_tracker.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                sleep_until_shutdown(&shutdown_requested, Duration::from_millis(100));
            }
            Err(e) => {
                emit_log(
                    "ERROR",
                    "uds_server",
                    None,
                    None,
                    None,
                    Some("accept"),
                    "FAILURE",
                    &format!("UDS accept failed: {}", e),
                    json_enabled,
                );
                sleep_until_shutdown(&shutdown_requested, Duration::from_millis(100));
            }
        }
    }

    let _ = fs::remove_file(socket_path);

    for _ in 0..50 {
        if active_connections.load(Ordering::SeqCst) == 0 {
            break;
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn handle_uds_stream(
    stream: UnixStream,
    registry: Arc<Mutex<RegistryMap>>,
    regex_rules: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>,
    id_extractor: Regex,
    whitelist: Vec<ipnet::IpNet>,
    table: String,
    json_enabled: bool,
    docker_socket_path: String,
    shutdown_requested: Arc<AtomicBool>,
) {
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(100))) {
        emit_log(
            "ERROR",
            "uds_server",
            None,
            None,
            None,
            Some("timeout_config"),
            "CRASH",
            &format!("Failed to enforce socket timeout: {}", e),
            json_enabled,
        );
        return;
    }

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();

    while !shutdown_requested.load(Ordering::SeqCst) {
        buf.clear();

        let mut chunk = reader.by_ref().take(8192);

        match chunk.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                let has_newline = buf.ends_with(&[b'\n']);

                if !has_newline && buf.len() >= 8192 {
                    emit_log(
                        "CRITICAL",
                        "uds_server",
                        None,
                        None,
                        None,
                        Some("stream"),
                        "TRUNCATED",
                        "UDS Line limit reached without delimiter. Discarding remainder safely.",
                        json_enabled,
                    );

                    let mut discard_buf = Vec::new();
                    match reader.read_until(b'\n', &mut discard_buf) {
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }

                let current_line = String::from_utf8_lossy(&buf);
                let trimmed = current_line.trim_end();

                evaluate_line_signatures(
                    trimmed,
                    &regex_rules,
                    &id_extractor,
                    &registry,
                    &whitelist,
                    &table,
                    json_enabled,
                    &docker_socket_path,
                    false,
                );
            }
            Err(_) => break,
        }
    }
}

fn evaluate_line_signatures(
    line: &str,
    rules: &[(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)],
    id_extractor: &Regex,
    registry: &Arc<Mutex<RegistryMap>>,
    whitelist: &[ipnet::IpNet],
    table: &str,
    json_enabled: bool,
    docker_socket_path: &str,
    is_from_file: bool,
) {
    for (rule_name, rx, try_act, final_act) in rules.iter() {
        if rx.is_match(line) {
            if let Some(caps) = id_extractor.captures(line) {
                if let Some(matched_id) = caps.get(1) {
                    let container_id = matched_id.as_str().to_string();

                    // TOCTOU Mitigation: Force ValidateState for all disk-based telemetry
                    let mut active_try = try_act.clone();
                    if is_from_file && active_try.first() != Some(&AtomicAction::ValidateState) {
                        active_try.insert(0, AtomicAction::ValidateState);
                    }

                    dispatch_to_worker(
                        registry,
                        container_id,
                        active_try,
                        final_act.clone(),
                        rule_name.clone(),
                        whitelist,
                        table,
                        json_enabled,
                        docker_socket_path,
                        line.to_string(),
                    );
                }
            }
        }
    }
}

fn dispatch_to_worker(
    registry: &Arc<Mutex<RegistryMap>>,
    container_id: String,
    try_actions: Vec<AtomicAction>,
    final_actions: Vec<AtomicAction>,
    rule_name: String,
    whitelist: &[ipnet::IpNet],
    table: &str,
    json_enabled: bool,
    docker_socket_path: &str,
    trigger_message: String,
) {
    const MAX_WORKERS: usize = 100;

    let mut reg = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if !reg.contains_key(&container_id) && reg.len() >= MAX_WORKERS {
        emit_log(
            "CRITICAL",
            "orchestrator",
            Some(&rule_name),
            Some(&container_id),
            None,
            Some("route"),
            "OOM_PREVENTION",
            "Maximum worker thread ceiling reached. Malicious ID flood detected. Payload dropped.",
            json_enabled,
        );
        return;
    }

    let tx = reg.entry(container_id.clone()).or_insert_with(|| {
        let (worker_tx, worker_rx) = sync_channel::<WorkerChannelMessage>(64);
        let cid_clone = container_id.clone();
        let wl_clone = whitelist.to_vec();
        let tbl_clone = table.to_string();
        let ds_clone = docker_socket_path.to_string();
        let reg_sharing_reference = Arc::clone(registry);

        thread::spawn(move || {
            run_worker_lifecycle(
                cid_clone,
                worker_rx,
                reg_sharing_reference,
                wl_clone,
                tbl_clone,
                json_enabled,
                ds_clone,
            );
        });

        worker_tx
    });

    match tx.try_send((
        try_actions,
        final_actions,
        rule_name.clone(),
        trigger_message,
    )) {
        Ok(_) => {}
        Err(TrySendError::Full(_)) => {
            emit_log(
                "CRITICAL",
                "orchestrator",
                Some(&rule_name),
                Some(&container_id),
                None,
                Some("route"),
                "DROPPED",
                "Worker execution queue full. Action dropped to prevent OOM.",
                json_enabled,
            );
        }
        Err(TrySendError::Disconnected(_)) => {
            emit_log(
                "ERROR",
                "orchestrator",
                Some(&rule_name),
                Some(&container_id),
                None,
                Some("route"),
                "FAIL",
                "Worker channel broken unexpectedly.",
                json_enabled,
            );
        }
    }
}

fn run_worker_lifecycle(
    container_id: String,
    rx_chan: Receiver<WorkerChannelMessage>,
    registry: Arc<Mutex<RegistryMap>>,
    whitelist: Vec<ipnet::IpNet>,
    table: String,
    json_enabled: bool,
    docker_socket_path: String,
) {
    let timeout_dur = Duration::from_secs(30);

    loop {
        match rx_chan.recv_timeout(timeout_dur) {
            Ok((try_cmds, final_cmds, rule, trigger_msg)) => {
                execute_containment_pipeline(
                    container_id.clone(),
                    try_cmds,
                    final_cmds,
                    whitelist.clone(),
                    table.clone(),
                    json_enabled,
                    rule,
                    docker_socket_path.clone(),
                    trigger_msg,
                );
            }
            Err(_) => {
                let mut reg = registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());

                match rx_chan.try_recv() {
                    Ok((try_cmds, final_cmds, rule, trigger_msg)) => {
                        drop(reg);

                        execute_containment_pipeline(
                            container_id.clone(),
                            try_cmds,
                            final_cmds,
                            whitelist.clone(),
                            table.clone(),
                            json_enabled,
                            rule,
                            docker_socket_path.clone(),
                            trigger_msg,
                        );
                    }
                    Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => {
                        reg.remove(&container_id);
                        break;
                    }
                }
            }
        }
    }
}

fn sleep_until_shutdown(shutdown_requested: &AtomicBool, duration: Duration) {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    let mut remaining = duration;

    while !shutdown_requested.load(Ordering::SeqCst) && remaining > Duration::ZERO {
        let sleep_for = remaining.min(POLL_INTERVAL);
        thread::sleep(sleep_for);
        remaining = remaining.saturating_sub(sleep_for);
    }
}

fn notify_systemd_watchdog() {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if !socket_path.is_empty() {
            use std::os::unix::net::UnixDatagram;

            let resolved_path = if let Some(stripped) = socket_path.strip_prefix('@') {
                format!("\0{}", stripped)
            } else {
                socket_path
            };

            if let Ok(socket) = UnixDatagram::unbound() {
                let _ = socket.send_to(b"WATCHDOG=1\n", resolved_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GuardConfig, IngestionMode, MonitorConfig};
    use regex::Regex;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    #[test]
    fn test_id_extractor_strict_boundaries() {
        let id_extractor = Regex::new(r"--id=\b([a-fA-F0-9]{12}|[a-fA-F0-9]{64})\b").unwrap();

        let valid_64 = "--id=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(
            id_extractor.is_match(valid_64),
            "Regex failed to match valid 64-char ID"
        );

        let valid_12 = "--id=a1b2c3d4e5f6";
        assert!(
            id_extractor.is_match(valid_12),
            "Regex failed to match valid 12-char ID"
        );

        let invalid_spoof = "--id=a1b2c3d4e5f67890a";
        assert!(
            !id_extractor.is_match(invalid_spoof),
            "SECURITY ALERT: Regex matched an unbounded invalid spoof ID"
        );

        let invalid_short = "--id=abc";
        assert!(
            !id_extractor.is_match(invalid_short),
            "SECURITY ALERT: Regex matched a malformed short ID"
        );
    }

    #[test]
    fn test_monitor_loop_returns_when_shutdown_already_requested() {
        let config = GuardConfig {
            monitor: MonitorConfig {
                mode: IngestionMode::File,
                log_dir: "/path/unused/when/shutdown/is/requested".to_string(),
                check_interval_ms: 1_000,
                ip_whitelist: vec!["127.0.0.1/32".parse().unwrap()],
                nftables_default_table: "inet filter".to_string(),
                json_logging_enabled: false,
                docker_socket_path: "/var/run/docker.sock".to_string(),
                systemd_watchdog_interval_ms: 0,
            },
            rules: Vec::new(),
        };

        let shutdown_requested = Arc::new(AtomicBool::new(true));
        let start = Instant::now();

        start_monitor_loop(config, shutdown_requested);

        assert!(
            start.elapsed() < Duration::from_millis(500),
            "monitor loop did not return promptly after shutdown was requested"
        );
    }
}

// Emits the systemd startup synchronization notification packet.
fn notify_systemd_ready() {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if !socket_path.is_empty() {
            use std::os::unix::net::UnixDatagram;

            let resolved_path = if let Some(stripped) = socket_path.strip_prefix('@') {
                format!("\0{}", stripped)
            } else {
                socket_path
            };

            if let Ok(socket) = UnixDatagram::unbound() {
                let _ = socket.send_to(b"READY=1\n", resolved_path);
            }
        }
    }
}

// Ingestion Pipeline Engine
// Operates high-performance file tailers and parallel UDS socket tracking pipelines cleanly.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
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

type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String);
type RegistryMap = HashMap<String, SyncSender<WorkerChannelMessage>>;

pub fn start_monitor_loop(config: GuardConfig) {
    let mode = &config.monitor.mode;
    let json_enabled = config.monitor.json_logging_enabled;
    let whitelist = config.monitor.ip_whitelist.clone();
    let table = config.monitor.nftables_default_table.clone();
    let docker_socket_path = config.monitor.docker_socket_path.clone();

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

    if mode == &IngestionMode::Socket || mode == &IngestionMode::Dual {
        let uds_registry = Arc::clone(&worker_registry);
        let uds_regex = Arc::clone(&regex_compiled);
        let uds_id_extractor = id_extractor.clone();
        let uds_whitelist = whitelist.clone();
        let uds_table = table.clone();
        let uds_socket_path = docker_socket_path.clone();

        thread::spawn(move || {
            run_uds_server(
                uds_registry,
                uds_regex,
                uds_id_extractor,
                uds_whitelist,
                uds_table,
                json_enabled,
                uds_socket_path,
            );
        });
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
        loop {
            thread::park();
        }
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

    loop {
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
                thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
                continue;
            }
        }

        let mut actively_seen_paths = HashSet::new();

        if let Ok(entries) = fs::read_dir(log_dir_path) {
            for entry in entries.flatten() {
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
                            scratchpad_buffer.clear();
                            let mut reached_eof = false;
                            let mut exceeded_limit = false;

                            loop {
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
        notify_systemd_watchdog();
        thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
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

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let reg_clone = Arc::clone(&registry);
            let rules_clone = Arc::clone(&regex_rules);
            let id_clone = id_extractor.clone();
            let wl_clone = whitelist.clone();
            let tbl_clone = table.clone();
            let ds_path_clone = docker_socket_path.clone();

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
                );
            });
        }
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

    loop {
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
) {
    for (rule_name, rx, try_act, final_act) in rules.iter() {
        if rx.is_match(line) {
            if let Some(caps) = id_extractor.captures(line) {
                if let Some(matched_id) = caps.get(1) {
                    let container_id = matched_id.as_str().to_string();

                    dispatch_to_worker(
                        registry,
                        container_id,
                        try_act.clone(),
                        final_act.clone(),
                        rule_name.clone(),
                        whitelist,
                        table,
                        json_enabled,
                        docker_socket_path,
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

    match tx.try_send((try_actions, final_actions, rule_name.clone())) {
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
            Ok((try_cmds, final_cmds, rule)) => {
                execute_containment_pipeline(
                    container_id.clone(),
                    try_cmds,
                    final_cmds,
                    whitelist.clone(),
                    table.clone(),
                    json_enabled,
                    rule,
                    docker_socket_path.clone(),
                );
            }
            Err(_) => {
                let mut reg = registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());

                match rx_chan.try_recv() {
                    Ok((try_cmds, final_cmds, rule)) => {
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
    use regex::Regex;

    #[test]
    fn test_id_extractor_strict_boundaries() {
        let id_extractor = Regex::new(r"--id=\b([a-fA-F0-9]{12}|[a-fA-F0-9]{64})\b").unwrap();

        let valid_64 = "--id=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(id_extractor.is_match(valid_64), "Regex failed to match valid 64-char ID");

        let valid_12 = "--id=a1b2c3d4e5f6";
        assert!(id_extractor.is_match(valid_12), "Regex failed to match valid 12-char ID");

        let invalid_spoof = "--id=a1b2c3d4e5f67890a";
        assert!(!id_extractor.is_match(invalid_spoof), "SECURITY ALERT: Regex matched an unbounded invalid spoof ID");

        let invalid_short = "--id=abc";
        assert!(!id_extractor.is_match(invalid_short), "SECURITY ALERT: Regex matched a malformed short ID");
    }
}
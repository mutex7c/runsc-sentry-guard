// Ingestion Pipeline Engine
// Operates high-performance file tailers and parallel UDS socket tracking pipelines cleanly.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

// Updated to ingest the centralized IngestionMode enumeration from the configuration profile space
use crate::config::{AtomicAction, GuardConfig, IngestionMode};
use crate::logger::emit_log;
use crate::worker::execute_containment_pipeline;

struct LogDescriptor {
    inode: u64,
    position: u64,
}

type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String);
type RegistryMap = HashMap<String, Sender<WorkerChannelMessage>>;

pub fn start_monitor_loop(config: GuardConfig) {
    // Read the explicit ingestion strategy mode from the monitor configuration segment
    let mode = &config.monitor.mode;
    let json_enabled = config.monitor.json_logging_enabled;
    let whitelist = config.monitor.ip_whitelist.clone();
    let table = config.monitor.nftables_default_table.clone();

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

    let id_extractor = Regex::new(r"--id=([a-fA-F0-9]{12,64})").unwrap();
    let mut file_state_tracker: HashMap<String, LogDescriptor> = HashMap::new();
    let mut first_run = true;

    // --- DEPLOYMENT MODE ROUTING BLOCKS ---

    // Option A: Spin up the UDS streaming server thread if Socket or Dual mode is explicitly enabled
    if mode == &IngestionMode::Socket || mode == &IngestionMode::Dual {
        let uds_registry = Arc::clone(&worker_registry);
        let uds_regex = Arc::clone(&regex_compiled);
        let uds_id_extractor = id_extractor.clone();
        let uds_whitelist = whitelist.clone();
        let uds_table = table.clone();
        thread::spawn(move || {
            run_uds_server(
                uds_registry,
                uds_regex,
                uds_id_extractor,
                uds_whitelist,
                uds_table,
                json_enabled,
            );
        });
    }

    // Option B: Short-circuit and freeze the main thread if configured strictly to Socket mode
    // This allows the UDS background thread to stream while bypassing all filesystem crawling loop CPU cycles
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
            thread::park(); // Puts the main execution thread into a permanent sleep state
        }
    }

    // Option C: Fall straight through into standard host directory log-tailing loops
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
                        let _ = reader.seek(SeekFrom::Start(last_pos));

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
                                    "Line limit hit. Payload ignored.",
                                    json_enabled,
                                );
                                break;
                            }

                            // Clean Deduplication: Invoking centralized line evaluator block
                            evaluate_line_signatures(
                                trimmed_line,
                                &regex_compiled,
                                &id_extractor,
                                &worker_registry,
                                &whitelist,
                                &table,
                                json_enabled,
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

// Out-of-band high-performance Unix Domain Socket server infrastructure engine
fn run_uds_server(
    registry: Arc<Mutex<RegistryMap>>,
    regex_rules: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>,
    id_extractor: Regex,
    whitelist: Vec<ipnet::IpNet>,
    table: String,
    json_enabled: bool,
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

    let _ = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660));

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let reg_clone = Arc::clone(&registry);
            let rules_clone = Arc::clone(&regex_rules);
            let id_clone = id_extractor.clone();
            let wl_clone = whitelist.clone();
            let tbl_clone = table.clone();

            thread::spawn(move || {
                handle_uds_stream(
                    stream,
                    reg_clone,
                    rules_clone,
                    id_clone,
                    wl_clone,
                    tbl_clone,
                    json_enabled,
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
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    while let Ok(bytes_read) = reader.read_line(&mut line) {
        if bytes_read == 0 {
            break;
        }
        let trimmed = line.trim_end();

        if trimmed.len() > 8192 {
            line.clear();
            continue;
        }

        // Clean Deduplication: Invoking centralized line evaluator block cleanly
        evaluate_line_signatures(
            trimmed,
            &regex_rules,
            &id_extractor,
            &registry,
            &whitelist,
            &table,
            json_enabled,
        );
        line.clear();
    }
}

// Centralized Reusable Ingestion Helper to evaluate string signatures cleanly
fn evaluate_line_signatures(
    line: &str,
    rules: &[(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)],
    id_extractor: &Regex,
    registry: &Arc<Mutex<RegistryMap>>,
    whitelist: &[ipnet::IpNet],
    table: &str,
    json_enabled: bool,
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
                    );
                }
            }
        }
    }
}

// Dispatches signature notifications safely across key-serialized downstream communication lines.
fn dispatch_to_worker(
    registry: &Arc<Mutex<RegistryMap>>,
    container_id: String,
    try_actions: Vec<AtomicAction>,
    final_actions: Vec<AtomicAction>,
    rule_name: String,
    whitelist: &[ipnet::IpNet],
    table: &str,
    json_enabled: bool,
) {
    // Replaced Match evaluation with idiomatic unwrap_or_else method call
    let mut reg = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let tx = reg.entry(container_id.clone()).or_insert_with(|| {
        let (worker_tx, worker_rx) = channel::<WorkerChannelMessage>();
        let cid_clone = container_id.clone();
        let wl_clone = whitelist.to_vec();
        let tbl_clone = table.to_string();
        let reg_sharing_reference = Arc::clone(registry);

        thread::spawn(move || {
            run_worker_lifecycle(
                cid_clone,
                worker_rx,
                reg_sharing_reference,
                wl_clone,
                tbl_clone,
                json_enabled,
            );
        });

        worker_tx
    });

    if let Err(e) = tx.send((try_actions, final_actions, rule_name.clone())) {
        emit_log(
            "ERROR",
            "orchestrator",
            Some(&rule_name),
            Some(&container_id),
            None,
            Some("route"),
            "FAIL",
            &format!("Channel broken: {}", e),
            json_enabled,
        );
    }
}

// Handles safe worker lifecycles, completely solving the 30-second reaper race condition.
fn run_worker_lifecycle(
    container_id: String,
    rx_chan: Receiver<WorkerChannelMessage>,
    registry: Arc<Mutex<RegistryMap>>,
    whitelist: Vec<ipnet::IpNet>,
    table: String,
    json_enabled: bool,
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

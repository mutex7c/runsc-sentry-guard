use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, OpenOptions}; // Cleaned up: Added OpenOptions here
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Conditionally import Unix file system extensions for flag manipulation
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::config::{AtomicAction, GuardConfig};
use crate::logger::emit_log;
use crate::worker::execute_containment_pipeline;

struct LogDescriptor {
    inode: u64,
    position: u64,
}

type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String);
type RegistryMap = HashMap<String, Sender<WorkerChannelMessage>>;

pub fn start_monitor_loop(config: GuardConfig) {
    let json_enabled = config.monitor.json_logging_enabled;
    let whitelist = config.monitor.ip_whitelist.clone();
    let table = config.monitor.nftables_default_table.clone();

    // Key-Based Registry map tracking active thread mailboxes
    let worker_registry: Arc<Mutex<RegistryMap>> = Arc::new(Mutex::new(HashMap::new()));

    // System call expression evaluation targets
    let regex_compiled: Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)> = config
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
        .collect();

    // ID verification rule bounds
    let id_extractor = Regex::new(r"--id=([a-fA-F0-9]{12,64})").unwrap();
    let mut file_state_tracker: HashMap<String, LogDescriptor> = HashMap::new();
    let mut first_run = true;

    emit_log(
        "INFO",
        "orchestrator",
        None,
        None,
        None,
        None,
        "STARTED",
        "Master directory observation thread loop armed successfully.",
        json_enabled,
    );

    loop {
        let log_dir_path = Path::new(&config.monitor.log_dir);

        // Dynamic cross-platform desktop initialization guard
        if !log_dir_path.exists() {
            #[cfg(not(target_os = "linux"))]
            {
                // Auto-create simulation targets on Desktop developer environments
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
                    "Target observation path does not exist on host file definitions.",
                    json_enabled,
                );
                thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
                continue;
            }
        }

        if let Ok(entries) = fs::read_dir(log_dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "boot") {
                    let path_str = path.to_string_lossy().into_owned();

                    #[cfg(target_os = "linux")]
                    let current_inode = {
                        use std::os::linux::fs::MetadataExt;
                        path.metadata().map(|m| m.st_ino()).unwrap_or(0)
                    };
                    #[cfg(not(target_os = "linux"))]
                    let current_inode = 0; // Mock profile for local desktop evaluations

                    // On the very first loop pass, establish a baseline position
                    // at the END of existing files to ignore historical lines.
                    if first_run {
                        if let Ok(metadata) = path.metadata() {
                            let file_len = metadata.len();
                            file_state_tracker.insert(
                                path_str.clone(),
                                LogDescriptor {
                                    inode: current_inode,
                                    position: file_len,
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

                    // Open file descriptors securely utilizing strict OS security constraints (Symlink defense)
                    #[cfg(unix)]
                    let file_result = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path);

                    #[cfg(not(unix))]
                    let file_result = File::open(&path); // Baseline cross-platform development workstation fallback

                    if let Ok(file) = file_result {
                        // Execute strict owner validation to defend against directory traversals / TOCTOU
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if let Ok(metadata) = file.metadata() {
                                if metadata.uid() != 0 {
                                    emit_log(
                                        "WARN",
                                        "orchestrator",
                                        None,
                                        None,
                                        None,
                                        Some("security_audit"),
                                        "REJECTED",
                                        &format!(
                                            "TOCTOU/Symlink intercept: File {} owner UID is {}, expected 0. Skipping log parsing loop.",
                                            path_str,
                                            metadata.uid()
                                        ),
                                        json_enabled,
                                    );
                                    continue;
                                }
                            }
                        }

                        let mut reader = BufReader::new(file);
                        let _ = reader.seek(SeekFrom::Start(last_pos));

                        // Process the streaming log blocks continuously
                        loop {
                            let mut line_bytes = Vec::new();
                            let mut reached_eof = false;
                            let mut exceeded_limit = false;

                            // Internal low-level buffer window parsing loop (OOM defense)
                            loop {
                                // Inspect the internal buffer without moving the file cursor
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

                                // Scan the memory slice for a newline delimiter
                                if let Some(newline_pos) =
                                    available_buffer.iter().position(|&b| b == b'\n')
                                {
                                    let consume_len = newline_pos + 1;

                                    if line_bytes.len() + consume_len > 8192 {
                                        exceeded_limit = true;
                                        let allowed_len = 8192 - line_bytes.len();
                                        line_bytes
                                            .extend_from_slice(&available_buffer[..allowed_len]);
                                        reader.consume(allowed_len);
                                    } else {
                                        line_bytes
                                            .extend_from_slice(&available_buffer[..consume_len]);
                                        reader.consume(consume_len);
                                    }
                                    break;
                                } else {
                                    // No newline in current chunk; consume the segment up to the limit
                                    let chunk_len = available_buffer.len();
                                    if line_bytes.len() + chunk_len > 8192 {
                                        exceeded_limit = true;
                                        let allowed_len = 8192 - line_bytes.len();
                                        line_bytes
                                            .extend_from_slice(&available_buffer[..allowed_len]);
                                        reader.consume(allowed_len);
                                        break;
                                    } else {
                                        line_bytes.extend_from_slice(available_buffer);
                                        reader.consume(chunk_len);
                                    }
                                }
                            }

                            // If we hit EOF and no bytes were fetched, we have fully processed the current file state
                            if reached_eof && line_bytes.is_empty() {
                                break;
                            }

                            // Convert the bounded byte array securely into a string view
                            let current_line = String::from_utf8_lossy(&line_bytes);
                            let trimmed_line = current_line.trim_end();

                            if exceeded_limit {
                                emit_log(
                                    "CRITICAL",
                                    "orchestrator",
                                    None,
                                    None,
                                    None,
                                    Some("stream_ingest"),
                                    "TRUNCATED",
                                    &format!(
                                        "Anomaly Identified: Log stream line length exceeded threshold limits in asset: {}. \
                                        Processing aborted to protect RAM channel boundaries.",
                                        path_str
                                    ),
                                    json_enabled,
                                );
                                break;
                            }

                            // Evaluate line strings against security signatures
                            for (rule_name, rx, try_act, final_act) in &regex_compiled {
                                if rx.is_match(trimmed_line) {
                                    if let Some(caps) = id_extractor.captures(trimmed_line) {
                                        if let Some(matched_id) = caps.get(1) {
                                            let container_id = matched_id.as_str().to_string();

                                            let mut registry = worker_registry.lock().unwrap();
                                            let tx = registry
                                                .entry(container_id.clone())
                                                .or_insert_with(|| {
                                                    let (tx, rx_chan) =
                                                        channel::<WorkerChannelMessage>();
                                                    let cid_clone = container_id.clone();
                                                    let wl_clone = whitelist.clone();
                                                    let tbl_clone = table.clone();
                                                    let reg_clone = Arc::clone(&worker_registry);

                                                    // Spawn self-reaping worker thread with 30s inactivity timeout
                                                    thread::spawn(move || {
                                                        let timeout_dur = Duration::from_secs(30);
                                                        loop {
                                                            match rx_chan.recv_timeout(timeout_dur)
                                                            {
                                                                Ok((
                                                                    try_cmds,
                                                                    final_cmds,
                                                                    rule,
                                                                )) => {
                                                                    execute_containment_pipeline(
                                                                        cid_clone.clone(),
                                                                        try_cmds,
                                                                        final_cmds,
                                                                        wl_clone.clone(),
                                                                        tbl_clone.clone(),
                                                                        json_enabled,
                                                                        rule,
                                                                    );
                                                                }
                                                                Err(_) => {
                                                                    // Inactivity timeout hit or sender dropped. Evict key from registry.
                                                                    let mut reg =
                                                                        reg_clone.lock().unwrap();
                                                                    reg.remove(&cid_clone);
                                                                    break; // Exit worker thread execution safely
                                                                }
                                                            }
                                                        }
                                                    });
                                                    tx
                                                });

                                            if let Err(err) = tx.send((
                                                try_act.clone(),
                                                final_act.clone(),
                                                rule_name.clone(),
                                            )) {
                                                emit_log(
                                                    "ERROR",
                                                    "orchestrator",
                                                    Some(rule_name),
                                                    Some(&container_id),
                                                    None,
                                                    Some("channel_route"),
                                                    "CRASH",
                                                    &format!(
                                                        "Internal pipeline channel synchronization broken: {}",
                                                        err
                                                    ),
                                                    json_enabled,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Sync position pointers tracking changes cleanly
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

        // Drop the first run flag after establishing the baseline tracking map
        first_run = false;

        // Handle Systemd native supervisor datagram heartbeat telemetry notifications
        notify_systemd_watchdog();
        thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
    }
}

fn notify_systemd_watchdog() {
    // Native out-of-band Systemd Notify Protocol Implementation
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if !socket_path.is_empty() {
            use std::os::unix::net::UnixDatagram;

            // Abstract namespace handling for Linux systemd configurations
            let resolved_path = if let Some(stripped) = socket_path.strip_prefix('@') {
                format!("\0{}", stripped)
            } else {
                socket_path
            };

            if let Ok(socket) = UnixDatagram::unbound() {
                let _ = socket.send_to(b"WATCHDOG=1\nREADY=1\n", resolved_path);
            }
        }
    }
}

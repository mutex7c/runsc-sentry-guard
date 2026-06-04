use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
                    let current_inode = 0;

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
                    if let Ok(file) = File::open(&path) {
                        let mut reader = BufReader::new(file);
                        let _ = reader.seek(SeekFrom::Start(last_pos));

                        loop {
                            let mut line_bytes = Vec::new();
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

                            if reached_eof && line_bytes.is_empty() {
                                break;
                            }

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

                                                    thread::spawn(move || {
                                                        // Set a strict 30-second channel timeout limit
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
                                                                    // Channel timed out or disconnected. Acquire registry lock.
                                                                    let mut reg =
                                                                        reg_clone.lock().unwrap();
                                                                    // Verify no new messages arrived right before locking
                                                                    reg.remove(&cid_clone);
                                                                    break; // Exit loop, terminating the thread cleanly
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

        first_run = false;
        notify_systemd_watchdog();
        thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
    }
}

fn notify_systemd_watchdog() {
    // Native Systemd Notify Protocol Implementation

    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if !socket_path.is_empty() {
            use std::os::unix::net::UnixDatagram;
            // Systemd sockets can use an abstract namespace path if prefixed with '@'
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

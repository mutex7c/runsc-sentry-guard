// Ingestion Pipeline Engine

// Operates fast file tailers and parallel UDS socket tracking pipelines
// Features active DoS-resistant TOCTOU mitigations, SO_PEERCRED trust boundaries, and lock safety

use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, RwLock}; // RwLock handles matrix validation and registry mapping
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use crate::config::{AtomicAction, GuardConfig, IngestionMode};
use crate::logger::emit_log;
use crate::worker::execute_containment_pipeline;

struct LogDescriptor {
    inode: u64,
    position: u64,
}

type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String, String);
type RegistryMap = HashMap<String, SyncSender<WorkerChannelMessage>>;

// Anti-DoS State Engine controlling the TOCTOU synchronous lookup fallback
#[allow(dead_code)]
struct AntiDosState {
    negative_cache: HashSet<String>,
    negative_queue: VecDeque<String>,
    tokens: u32,
    last_refill: Instant,
}

#[allow(dead_code)]
const MAX_NEGATIVE_CACHE: usize = 1000;
#[allow(dead_code)]
const MAX_LOOKUP_TOKENS: u32 = 10; // Max API queries per second for unknown IDs

pub fn start_monitor_loop(config: GuardConfig) {
    let mode = &config.monitor.mode;
    let json_enabled = config.monitor.json_logging_enabled;
    let docker_socket_path = config.monitor.docker_socket_path.clone();
    let watchdog_interval = config.monitor.systemd_watchdog_interval_ms;

    // Prevent expensive heap cloning during incident routing
    let whitelist = Arc::new(config.monitor.ip_whitelist);
    let table = Arc::new(config.monitor.nftables_default_table);

    // Spawn a dedicated, decoupled watchdog heartbeat thread
    if watchdog_interval > 0 {
        thread::spawn(move || {
            loop {
                notify_systemd_watchdog();
                thread::sleep(Duration::from_millis(watchdog_interval));
            }
        });
    }

    // Initialize the shared thread-safe container ID cache
    let active_containers = Arc::new(RwLock::new(HashSet::<String>::new()));

    // Initialize the DoS mitigation state
    let anti_dos_state = Arc::new(Mutex::new(AntiDosState {
        negative_cache: HashSet::new(),
        negative_queue: VecDeque::new(),
        tokens: MAX_LOOKUP_TOKENS,
        last_refill: Instant::now(),
    }));

    // Detached event-driven background thread utilizing zero-delay socket streaming context
    #[cfg(target_os = "linux")]
    {
        let cache_clone = Arc::clone(&active_containers);
        let ds_path = docker_socket_path.clone();

        thread::spawn(move || {
            use std::io::Write;

            // Target container filter query string explicitly tracking asset creation and destruction
            let stream_endpoint = "/events?filters=%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22start%22%2C%22die%22%5D%7D";

            loop {
                if let Ok(mut stream) = UnixStream::connect(&ds_path) {

                    // Re-seed the cache immediately upon initial connection and
                    // any subsequent reconnection, to prevent state drift blind spots
                    let current_ids = crate::worker::fetch_running_container_ids(&ds_path);
                    if let Ok(mut guard) = cache_clone.write() {
                        *guard = current_ids;
                    }

                    let request = format!(
                        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                        stream_endpoint
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut reader = BufReader::new(stream);
                        let mut status_ok = false;
                        let mut is_chunked = false;
                        let mut header_count = 0;

                        // Parse HTTP response headers safely up to a strict line ceiling
                        while header_count < 100 {
                            let mut header_line = String::new();
                            if reader.read_line(&mut header_line).is_err() {
                                break;
                            }
                            let trimmed = header_line.trim();
                            if trimmed.is_empty() {
                                break;
                            }
                            if header_line.starts_with("HTTP/1.1 200")
                                || header_line.starts_with("HTTP/1.0 200")
                            {
                                status_ok = true;
                            }
                            let lower = trimmed.to_lowercase();
                            if lower.starts_with("transfer-encoding:") && lower.contains("chunked")
                            {
                                is_chunked = true;
                            }
                            header_count += 1;
                        }

                        // Stream processing loop with native HTTP chunk-unwrapping
                        if status_ok && is_chunked {
                            let mut chunk_size_buf = String::new();

                            loop {
                                chunk_size_buf.clear();
                                if reader.read_line(&mut chunk_size_buf).is_err() {
                                    break;
                                }
                                let trimmed_size = chunk_size_buf.trim();
                                if trimmed_size.is_empty() {
                                    continue;
                                }

                                // Convert hex chunk sizes directly to byte lengths
                                let chunk_size = match usize::from_str_radix(trimmed_size, 16) {
                                    Ok(size) => size,
                                    Err(_) => break,
                                };

                                if chunk_size == 0 {
                                    break; // Stream termination boundary reached
                                }

                                let mut chunk_buf = vec![0u8; chunk_size];
                                if reader.read_exact(&mut chunk_buf).is_err() {
                                    break;
                                }

                                // Consume trailing carriage return line feeds bound to chunk limits
                                let mut crlf = [0u8; 2];
                                if reader.read_exact(&mut crlf).is_err() {
                                    break;
                                }

                                let payload_str = String::from_utf8_lossy(&chunk_buf);
                                for line in payload_str.lines() {
                                    if let Ok(event) = serde_json::from_str::<
                                        crate::worker::DockerEventPayload,
                                    >(line)
                                    {
                                        if let Ok(mut guard) = cache_clone.write() {
                                            if event.action == "start" {
                                                guard.insert(event.actor.id);
                                            } else if event.action == "die" {
                                                guard.remove(&event.actor.id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Secure connection retry backing delay handling socket crashes gracefully
                thread::sleep(Duration::from_secs(1));
            }
        });
    }

    let worker_registry: Arc<RwLock<RegistryMap>> = Arc::new(RwLock::new(HashMap::new()));

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
        let uds_whitelist = Arc::clone(&whitelist);
        let uds_table = Arc::clone(&table);
        let uds_socket_path = docker_socket_path.clone();
        let uds_cache = Arc::clone(&active_containers);
        let uds_anti_dos = Arc::clone(&anti_dos_state);

        thread::spawn(move || {
            run_uds_server(
                uds_registry,
                uds_regex,
                uds_id_extractor,
                uds_whitelist,
                uds_table,
                json_enabled,
                uds_socket_path,
                uds_cache,
                uds_anti_dos,
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

    if mode == &IngestionMode::File {
        notify_systemd_ready();
    }

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

        // File Spoofing Mitigation: Strict Directory Ownership & Permission Audit
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(metadata) = log_dir_path.metadata() {
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
                    thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
                    continue;
                }
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
                    let file_result = open_log_safe(log_dir_path, path.file_name().unwrap());

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

                        // 64 KB Line-bounded streaming evaluator defeats
                        // truncation padding and prevents context leakage
                        const MAX_LINE_SIZE: usize = 65536;
                        let mut stream_buffer = vec![0u8; MAX_LINE_SIZE * 2];
                        let mut buffer_len = 0;

                        loop {
                            let bytes_read = match reader.read(&mut stream_buffer[buffer_len..]) {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(_) => break,
                            };

                            buffer_len += bytes_read;
                            let mut start_pos = 0;

                            // Process complete discrete lines found inside the buffer segment
                            while let Some(newline_offset) = stream_buffer[start_pos..buffer_len]
                                .iter()
                                .position(|&b| b == b'\n')
                            {
                                let end_pos = start_pos + newline_offset;
                                let line_slice =
                                    String::from_utf8_lossy(&stream_buffer[start_pos..end_pos]);
                                let trimmed = line_slice.trim_end();

                                if !trimmed.is_empty() {
                                    evaluate_line_signatures(
                                        trimmed,
                                        &regex_compiled,
                                        &id_extractor,
                                        &worker_registry,
                                        &whitelist,
                                        &table,
                                        json_enabled,
                                        &docker_socket_path,
                                        true,
                                        &active_containers,
                                        &anti_dos_state,
                                    );
                                }
                                start_pos = end_pos + 1;
                            }

                            // Shift incomplete trail fragments to the buffer head
                            if start_pos < buffer_len {
                                let remainder_len = buffer_len - start_pos;
                                if remainder_len >= MAX_LINE_SIZE {
                                    emit_log(
                                        "CRITICAL",
                                        "orchestrator",
                                        None,
                                        None,
                                        None,
                                        Some("stream"),
                                        "OVERFLOW_FLUSHED",
                                        "Line length exceeded 64KB security threshold. Flushing stream segment to guarantee stability.",
                                        json_enabled,
                                    );
                                    buffer_len = 0;
                                } else {
                                    stream_buffer.copy_within(start_pos..buffer_len, 0);
                                    buffer_len = remainder_len;
                                }
                            } else {
                                buffer_len = 0;
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

        file_state_tracker.retain(|path_key, _| actively_seen_paths.contains(path_key));
        first_run = false;
        thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
    }
}

#[cfg(target_os = "linux")]
fn get_peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if res == 0 {
        Ok(ucred.uid)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn run_uds_server(
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashSet<String>>>,
    anti_dos_state: Arc<Mutex<AntiDosState>>,
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

    notify_systemd_ready();

    let active_connections = Arc::new(AtomicUsize::new(0));
    const MAX_UDS_CONNECTIONS: usize = 50;

    for stream in listener.incoming() {
        if let Ok(stream) = stream {

            // Extract Peer Credentials using raw libc to bypass unstable std features
            #[cfg(target_os = "linux")]
            {
                if let Ok(peer_uid) = get_peer_uid(&stream) {
                    // Reject connection if not root (or map specifically to 'docker' group if required)
                    if peer_uid != 0 {
                        emit_log(
                            "WARN",
                            "uds_server",
                            None,
                            None,
                            None,
                            Some("trust_boundary"),
                            "REJECTED",
                            &format!("Unauthorized UID {} attempted UDS connection. Payload dropped.", peer_uid),
                            json_enabled,
                        );
                        continue;
                    }
                } else {
                    continue; // Drop unverified origins safely
                }
            }

            if active_connections.load(Ordering::SeqCst) >= MAX_UDS_CONNECTIONS {
                continue;
            }

            active_connections.fetch_add(1, Ordering::SeqCst);
            let conn_tracker = Arc::clone(&active_connections);

            let reg_clone = Arc::clone(&registry);
            let rules_clone = Arc::clone(&regex_rules);
            let id_clone = id_extractor.clone();
            let wl_clone = Arc::clone(&whitelist);
            let tbl_clone = Arc::clone(&table);
            let ds_path_clone = docker_socket_path.clone();
            let cache_clone = Arc::clone(&active_containers);
            let dos_clone = Arc::clone(&anti_dos_state);

            thread::spawn(move || {
                let _guard = ConnectionGuard(conn_tracker);
                handle_uds_stream(
                    stream,
                    reg_clone,
                    rules_clone,
                    id_clone,
                    wl_clone,
                    tbl_clone,
                    json_enabled,
                    ds_path_clone,
                    cache_clone,
                    dos_clone,
                );
            });
        }
    }
}

fn handle_uds_stream(
    stream: UnixStream,
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashSet<String>>>,
    anti_dos_state: Arc<Mutex<AntiDosState>>,
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
                    false,
                    &active_containers,
                    &anti_dos_state,
                );
            }
            Err(_) => break,
        }
    }
}

// Synchronous Fast-Path to close TOCTOU gap
#[cfg(target_os = "linux")]
fn is_container_active_sync(container_id: &str, socket_path: &str) -> bool {
    use std::io::{BufRead, Write};

    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let request = format!("GET /containers/{}/json HTTP/1.0\r\n\r\n", container_id);

        if stream.write_all(request.as_bytes()).is_ok() {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                // If Docker returns an HTTP 200, the container actively exists
                return line.contains(" 200 ");
            }
        }
    }
    false
}

fn evaluate_line_signatures(
    line: &str,
    rules: &[(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)],
    id_extractor: &Regex,
    registry: &Arc<RwLock<RegistryMap>>,
    whitelist: &Arc<Vec<ipnet::IpNet>>,
    table: &Arc<String>,
    json_enabled: bool,
    docker_socket_path: &str,
    is_from_file: bool,
    active_containers: &Arc<RwLock<HashSet<String>>>,
    anti_dos_state: &Arc<Mutex<AntiDosState>>,
) {
    // Consume variables on non-Linux targets to silence compiler warnings
    #[cfg(not(target_os = "linux"))]
    {
        let _ = active_containers;
        let _ = anti_dos_state;
    }

    for (rule_name, rx, try_act, final_act) in rules.iter() {
        if rx.is_match(line) {
            if let Some(caps) = id_extractor.captures(line) {
                if let Some(matched_id) = caps.get(1) {
                    let container_id = matched_id.as_str().to_string();

                    #[cfg(target_os = "linux")]
                    {
                        let mut is_valid = {
                            let active_guard = active_containers.read().expect("CRITICAL: Active container cache lock poisoned. Aborting.");
                            active_guard.contains(&container_id)
                                || active_guard.iter().any(|long_id| long_id.starts_with(&container_id))
                        };

                        // Fallback: Synchronous Verification mapped behind Negative Cache & Rate Limits
                        if !is_valid {
                            let mut dos_guard = anti_dos_state.lock().expect("CRITICAL: DoS State lock poisoned. Aborting.");

                            // Token Replenishment
                            let now = Instant::now();
                            if now.duration_since(dos_guard.last_refill).as_secs() >= 1 {
                                dos_guard.tokens = MAX_LOOKUP_TOKENS;
                                dos_guard.last_refill = now;
                            }

                            // Bypass check if attacker is hitting known bad IDs
                            if dos_guard.negative_cache.contains(&container_id) {
                                continue;
                            }

                            if dos_guard.tokens > 0 {
                                dos_guard.tokens -= 1;
                                drop(dos_guard); // Free lock immediately during active I/O

                                let actually_exists = is_container_active_sync(&container_id, docker_socket_path);

                                if actually_exists {
                                    let mut active_write = active_containers.write().expect("CRITICAL: Active container cache lock poisoned. Aborting.");
                                    active_write.insert(container_id.clone());
                                    is_valid = true;
                                } else {
                                    let mut dos_write = anti_dos_state.lock().expect("CRITICAL: DoS State lock poisoned. Aborting.");

                                    // Maintain bounded LRU capacity for Negative Cache
                                    if dos_write.negative_cache.len() >= MAX_NEGATIVE_CACHE {
                                        if let Some(oldest) = dos_write.negative_queue.pop_front() {
                                            dos_write.negative_cache.remove(&oldest);
                                        }
                                    }
                                    dos_write.negative_cache.insert(container_id.clone());
                                    dos_write.negative_queue.push_back(container_id.clone());
                                }
                            } else {
                                // ID Exhaustion flood detected
                                // Drop payload cleanly to protect the engine
                                emit_log(
                                    "WARN",
                                    "orchestrator",
                                    None,
                                    None,
                                    None,
                                    Some("api_rate_limit"),
                                    "DROPPED",
                                    "Container lookup token pool exhausted. Payload discarded.",
                                    json_enabled,
                                );
                                continue;
                            }
                        }

                        if !is_valid {
                            continue;
                        }
                    }

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
                        Arc::clone(whitelist),
                        Arc::clone(table),
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
    registry: &Arc<RwLock<RegistryMap>>,
    container_id: String,
    try_actions: Vec<AtomicAction>,
    final_actions: Vec<AtomicAction>,
    rule_name: String,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    docker_socket_path: &str,
    trigger_message: String,
) {
    const MAX_WORKERS: usize = 100;

    // FAST PATH: Acquire parallel, non-blocking read lock
    // to pass telemetry frames on active mailboxes
    {
        let reg_read = registry
            .read()
            .expect("CRITICAL: Worker registry lock poisoned. Aborting.");
        if let Some(tx) = reg_read.get(&container_id) {
            let _ = tx.try_send((try_actions, final_actions, rule_name, trigger_message));
            return;
        }
    }

    // SLOW PATH: Channel context does not exist
    // Acquire exclusive write lock to initialize pipeline workers
    let mut reg_write = registry
        .write()
        .expect("CRITICAL: Worker registry lock poisoned. Aborting.");

    // Double-Checked Locking Pattern validation check
    if !reg_write.contains_key(&container_id) && reg_write.len() >= MAX_WORKERS {
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

    let tx = reg_write.entry(container_id.clone()).or_insert_with(|| {
        let (worker_tx, worker_rx) = sync_channel::<WorkerChannelMessage>(64);
        let cid_clone = container_id.clone();
        let wl_clone = Arc::clone(&whitelist);
        let tbl_clone = Arc::clone(&table);
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
    registry: Arc<RwLock<RegistryMap>>,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
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
                    Arc::clone(&whitelist),
                    Arc::clone(&table),
                    json_enabled,
                    rule,
                    docker_socket_path.clone(),
                    trigger_msg,
                );
            }
            Err(_) => {
                // Decay phase
                // Acquire exclusive write lock strictly on worker termination
                let mut reg = registry
                    .write()
                    .expect("CRITICAL: Worker registry lock poisoned. Aborting.");

                match rx_chan.try_recv() {
                    Ok((try_cmds, final_cmds, rule, trigger_msg)) => {
                        drop(reg);

                        execute_containment_pipeline(
                            container_id.clone(),
                            try_cmds,
                            final_cmds,
                            Arc::clone(&whitelist),
                            Arc::clone(&table),
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
}

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

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(unix)]
fn open_log_safe(dir_path: &Path, file_name: &OsStr) -> std::io::Result<fs::File> {
    let dir_c = CString::new(dir_path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let file_c = CString::new(file_name.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    unsafe {
        let dir_fd = libc::open(
            dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if dir_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let file_fd = libc::openat(
            dir_fd,
            file_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        );
        libc::close(dir_fd);

        if file_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(fs::File::from_raw_fd(file_fd))
    }
}
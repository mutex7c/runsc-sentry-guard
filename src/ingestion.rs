use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::thread;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

#[cfg(target_os = "linux")]
use std::io::BufRead;

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use crate::config::{
    AtomicAction, GuardConfig, IngestionMode, JsonRuleConfig, LogLevel, PlaybookConfig,
    RegistryMap, WorkerChannelMessage,
};
use crate::limiters::{AntiDosState, GlobalRateLimiter};
use crate::logger::emit_log;
use crate::worker::execute_containment_pipeline;

struct LogDescriptor {
    inode: u64,
    position: u64,
}

pub fn start_monitor_loop(
    config: GuardConfig,
    initial_playbooks: HashMap<String, PlaybookConfig>,
    initial_rules: Vec<JsonRuleConfig>,
    shutdown: Arc<AtomicBool>,
    config_path: String,
) {
    let mode = &config.monitor.mode;
    let json_enabled = config.monitor.json_logging_enabled;
    let config_log_level = config.monitor.log_level;
    let docker_socket_path = config.monitor.docker_socket_path.clone();
    let watchdog_interval = config.monitor.systemd_watchdog_interval_ms;
    let max_workers = config.monitor.max_workers;

    let whitelist = Arc::new(config.monitor.ip_whitelist);
    let table = Arc::new(config.monitor.nftables_default_table);

    if watchdog_interval > 0 {
        let watchdog_shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            while !watchdog_shutdown.load(Ordering::SeqCst) {
                notify_systemd_watchdog();
                thread::sleep(Duration::from_millis(watchdog_interval));
            }
        });
    }

    let active_containers = Arc::new(RwLock::new(HashSet::<String>::new()));
    let anti_dos_state = Arc::new(Mutex::new(AntiDosState::new()));
    let global_limiter = Arc::new(GlobalRateLimiter::new(10000));

    #[cfg(target_os = "linux")]
    {
        let cache_clone = Arc::clone(&active_containers);
        let ds_path = docker_socket_path.clone();
        let stream_shutdown = Arc::clone(&shutdown);

        thread::spawn(move || {
            use std::io::{Cursor, Read, Write};
            let stream_endpoint = "/events?filters=%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22start%22%2C%22die%22%5D%7D";

            while !stream_shutdown.load(Ordering::SeqCst) {
                match std::os::unix::net::UnixStream::connect(&ds_path) {
                    Ok(mut stream) => {
                        let current_ids = crate::worker::fetch_running_container_ids(&ds_path);
                        {
                            let mut guard = cache_clone.write();
                            *guard = current_ids;
                        }

                        let request = format!(
                            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                            stream_endpoint
                        );

                        if stream.write_all(request.as_bytes()).is_ok() {
                            let mut header_buf = [0u8; 8192];
                            let mut bytes_read = 0;
                            let mut header_end = 0;
                            let mut status_ok = false;
                            let mut is_chunked = false;

                            loop {
                                if bytes_read >= header_buf.len() {
                                    break;
                                }
                                let n = match stream.read(&mut header_buf[bytes_read..]) {
                                    Ok(n) if n > 0 => n,
                                    _ => break,
                                };
                                bytes_read += n;

                                let mut headers = [httparse::EMPTY_HEADER; 64];
                                let mut res = httparse::Response::new(&mut headers);

                                match res.parse(&header_buf[..bytes_read]) {
                                    Ok(httparse::Status::Complete(body_start_offset)) => {
                                        header_end = body_start_offset;
                                        if let Some(code) = res.code {
                                            if code == 200 {
                                                status_ok = true;
                                            }
                                        }
                                        for header in res.headers {
                                            let name = header.name.to_lowercase();
                                            let value = String::from_utf8_lossy(header.value)
                                                .to_lowercase();
                                            if name == "transfer-encoding"
                                                && value.contains("chunked")
                                            {
                                                is_chunked = true;
                                            }
                                        }
                                        break;
                                    }
                                    Ok(httparse::Status::Partial) => continue,
                                    Err(_) => break,
                                }
                            }

                            if status_ok && is_chunked {
                                let leftover = header_buf[header_end..bytes_read].to_vec();
                                let mut reader =
                                    BufReader::new(Cursor::new(leftover).chain(stream));
                                let mut chunk_size_buf = String::new();
                                let mut line_buffer = Vec::new();

                                while !stream_shutdown.load(Ordering::SeqCst) {
                                    chunk_size_buf.clear();
                                    if reader.read_line(&mut chunk_size_buf).is_err() {
                                        break;
                                    }
                                    let trimmed_size = chunk_size_buf.trim();
                                    if trimmed_size.is_empty() {
                                        continue;
                                    }

                                    let chunk_size = match usize::from_str_radix(trimmed_size, 16) {
                                        Ok(size) => size,
                                        Err(_) => break,
                                    };
                                    if chunk_size == 0 {
                                        break;
                                    }

                                    let mut chunk_buf = vec![0u8; chunk_size];
                                    if reader.read_exact(&mut chunk_buf).is_err() {
                                        break;
                                    }

                                    let mut crlf = [0u8; 2];
                                    if reader.read_exact(&mut crlf).is_err() {
                                        break;
                                    }

                                    line_buffer.extend_from_slice(&chunk_buf);
                                    if line_buffer.len() > 65536 {
                                        line_buffer.clear();
                                    }

                                    let mut start_pos = 0;
                                    while let Some(newline_offset) =
                                        line_buffer[start_pos..].iter().position(|&b| b == b'\n')
                                    {
                                        let end_pos = start_pos + newline_offset;
                                        let line_slice = String::from_utf8_lossy(
                                            &line_buffer[start_pos..end_pos],
                                        );
                                        let trimmed = line_slice.trim_end();

                                        if !trimmed.is_empty() {
                                            if let Ok(event) = serde_json::from_str::<
                                                crate::worker::DockerEventPayload,
                                            >(
                                                trimmed
                                            ) {
                                                let mut guard = cache_clone.write();
                                                if event.action == "start" {
                                                    guard.insert(event.actor.id);
                                                } else if event.action == "die" {
                                                    guard.remove(&event.actor.id);
                                                }
                                            }
                                        }
                                        start_pos = end_pos + 1;
                                    }
                                    if start_pos > 0 {
                                        line_buffer.drain(0..start_pos);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        emit_log(
                            "ERROR",
                            "orchestrator",
                            None,
                            None,
                            None,
                            Some("runtime_ipc"),
                            "DISCONNECTED",
                            &format!(
                                "Container engine socket link unavailable. Retrying: {:#}",
                                e
                            ),
                            config_log_level,
                            json_enabled,
                        );
                    }
                }

                if stream_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
    }

    let worker_registry: Arc<RwLock<RegistryMap>> = Arc::new(RwLock::new(HashMap::new()));

    let regex_compiled = Arc::new(RwLock::new(compile_manifest_rules(
        &initial_rules,
        &initial_playbooks,
    )));

    let rules_watch_clone = Arc::clone(&regex_compiled);
    let path_watch_clone = config_path.clone();
    let json_enabled_clone = json_enabled;

    thread::spawn(move || {
        use notify::{RecursiveMode, Watcher};
        let (tx, rx) = std::sync::mpsc::channel();

        let watcher_res =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() || event.kind.is_create() {
                        if let Err(e) = tx.send(()) {
                            eprintln!(
                                "[CRITICAL] Hot-reload notification pipeline broken: {:#}",
                                e
                            );
                        }
                    }
                }
            });

        if let Ok(mut watcher) = watcher_res {
            if watcher
                .watch(Path::new(&path_watch_clone), RecursiveMode::NonRecursive)
                .is_ok()
            {
                while rx.recv().is_ok() {
                    thread::sleep(Duration::from_millis(100));

                    if let Ok(new_config) = crate::config::load_config(&path_watch_clone) {
                        if let Ok((new_playbooks, new_rules)) =
                            crate::config::load_and_merge_manifests(
                                &new_config.monitor.security_manifest_paths,
                            )
                        {
                            let new_compiled = compile_manifest_rules(&new_rules, &new_playbooks);
                            {
                                let mut guard = rules_watch_clone.write();
                                *guard = new_compiled;
                            }
                            emit_log(
                                "INFO",
                                "config_reload",
                                None,
                                None,
                                None,
                                None,
                                "SUCCESS",
                                "Active rulesets and decoupled manifests hot-reloaded.",
                                config_log_level,
                                json_enabled_clone,
                            );
                        } else {
                            emit_log(
                                "WARN",
                                "config_reload",
                                None,
                                None,
                                None,
                                None,
                                "FAILURE",
                                "Hot-reload aborted: Manifest files contain schema errors or name collisions.",
                                config_log_level,
                                json_enabled_clone,
                            );
                        }
                    } else {
                        emit_log(
                            "WARN",
                            "config_reload",
                            None,
                            None,
                            None,
                            None,
                            "FAILURE",
                            "Hot-reload aborted: Updated config.toml contains errors.",
                            config_log_level,
                            json_enabled_clone,
                        );
                    }
                }
            }
        }
    });

    let id_extractor = Regex::new(r"--id=\b([a-fA-F0-9]{12}|[a-fA-F0-9]{64})\b").unwrap();
    let filename_id_extractor = Regex::new(r"\b([a-fA-F0-9]{12}|[a-fA-F0-9]{64})\b").unwrap();

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
        let uds_shutdown = Arc::clone(&shutdown);
        let limiter_clone = Arc::clone(&global_limiter);

        thread::spawn(move || {
            crate::socket::run_uds_server(
                uds_registry,
                uds_regex,
                uds_id_extractor,
                uds_whitelist,
                uds_table,
                json_enabled,
                config_log_level,
                uds_socket_path,
                uds_cache,
                uds_anti_dos,
                uds_shutdown,
                max_workers,
                limiter_clone,
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
            "Out-of-band UDS receiver active. Filesystem parsing idle.",
            config_log_level,
            json_enabled,
        );
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));
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
        "Master directory tailer and UDS receiver paths armed.",
        config_log_level,
        json_enabled,
    );

    if mode == &IngestionMode::File {
        notify_systemd_ready();
    }

    while !shutdown.load(Ordering::SeqCst) {
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
                    config_log_level,
                    json_enabled,
                );
                thread::sleep(Duration::from_millis(config.monitor.check_interval_ms));
                continue;
            }
        }

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
                        "Log directory unsecured. Suspended to prevent spoofing.",
                        config_log_level,
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

                    let file_name_str = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    let file_container_id = filename_id_extractor
                        .captures(file_name_str)
                        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
                    if file_container_id.is_none() {
                        continue;
                    }

                    #[cfg(target_os = "linux")]
                    let current_inode = {
                        use std::os::unix::fs::MetadataExt;
                        path.metadata().map(|m| m.ino()).unwrap_or(0)
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
                        if reader.seek(SeekFrom::Start(last_pos)).is_err() {
                            continue;
                        }

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

                            while let Some(newline_offset) = stream_buffer[start_pos..buffer_len]
                                .iter()
                                .position(|&b| b == b'\n')
                            {
                                let end_pos = start_pos + newline_offset;
                                let line_slice =
                                    String::from_utf8_lossy(&stream_buffer[start_pos..end_pos]);
                                let trimmed = line_slice.trim_end();

                                if !trimmed.is_empty() {
                                    let rules_guard = regex_compiled.read();
                                    evaluate_line_signatures(
                                        trimmed,
                                        &rules_guard,
                                        &id_extractor,
                                        &worker_registry,
                                        &whitelist,
                                        &table,
                                        json_enabled,
                                        config_log_level,
                                        &docker_socket_path,
                                        file_container_id.clone(),
                                        true,
                                        &active_containers,
                                        &anti_dos_state,
                                        max_workers,
                                        &global_limiter,
                                    );
                                }
                                start_pos = end_pos + 1;
                            }

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
                                        "Line token bounds overflowed 64KB boundary.",
                                        config_log_level,
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
fn is_container_active_sync(container_id: &str, socket_path: &str) -> bool {
    use std::io::{Read, Write};
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket_path) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let request = format!("GET /containers/{}/json HTTP/1.0\r\n\r\n", container_id);

        if stream.write_all(request.as_bytes()).is_ok() {
            let mut header_buf = [0u8; 1024];
            let mut bytes_read = 0;

            loop {
                if bytes_read >= header_buf.len() {
                    break;
                }
                match stream.read(&mut header_buf[bytes_read..]) {
                    Ok(n) if n > 0 => bytes_read += n,
                    _ => break,
                }

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut res = httparse::Response::new(&mut headers);

                match res.parse(&header_buf[..bytes_read]) {
                    Ok(httparse::Status::Complete(_)) => {
                        return res.code == Some(200);
                    }
                    Ok(httparse::Status::Partial) => continue,
                    Err(_) => break,
                }
            }
        }
    }
    false
}

#[allow(unused_variables)]
pub fn evaluate_line_signatures(
    line: &str,
    rules: &[(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)],
    id_extractor: &Regex,
    registry: &Arc<RwLock<RegistryMap>>,
    whitelist: &Arc<Vec<ipnet::IpNet>>,
    table: &Arc<String>,
    json_enabled: bool,
    config_log_level: LogLevel,
    docker_socket_path: &str,
    file_container_id: Option<String>,
    is_from_file: bool,
    active_containers: &Arc<RwLock<HashSet<String>>>,
    anti_dos_state: &Arc<Mutex<AntiDosState>>,
    max_workers: usize,
    global_limiter: &GlobalRateLimiter,
) {
    if !global_limiter.acquire() {
        if global_limiter.should_warn() {
            emit_log(
                "WARN",
                "orchestrator",
                None,
                None,
                None,
                Some("rate_limit"),
                "THROTTLED",
                "Global log ingestion ceiling reached.",
                config_log_level,
                json_enabled,
            );
        }
        return;
    }

    for (rule_name, rx, try_act, final_act) in rules.iter() {
        emit_log(
            "DEBUG",
            "orchestrator",
            None,
            None,
            None,
            Some("signature_eval"),
            "EVALUATING",
            &format!(
                "Scanning active stream sequences against signature layout: '{}'",
                rule_name
            ),
            config_log_level,
            json_enabled,
        );

        if rx.is_match(line) {
            let container_id = if let Some(ref id) = file_container_id {
                id.clone()
            } else if !is_from_file {
                emit_log(
                    "WARN",
                    "uds_server",
                    Some(rule_name),
                    None,
                    None,
                    Some("trust_boundary"),
                    "REJECTED",
                    "Socket stream failed kernel identity resolution. Dropping unauthenticated payload.",
                    config_log_level,
                    json_enabled,
                );
                continue;
            } else if let Some(caps) = id_extractor.captures(line) {
                if let Some(matched_id) = caps.get(1) {
                    matched_id.as_str().to_string()
                } else {
                    continue;
                }
            } else {
                continue;
            };

            #[cfg(target_os = "linux")]
            {
                let mut is_valid = {
                    let active_guard = active_containers.read();
                    active_guard.contains(&container_id)
                        || active_guard
                            .iter()
                            .any(|long_id| long_id.starts_with(&container_id))
                };

                if !is_valid {
                    let mut dos_guard = anti_dos_state.lock();
                    let now = std::time::Instant::now();
                    if now.duration_since(dos_guard.last_refill).as_secs() >= 1 {
                        dos_guard.tokens = crate::limiters::MAX_LOOKUP_TOKENS;
                        dos_guard.last_refill = now;
                    }

                    if dos_guard.negative_cache.contains(&container_id) {
                        continue;
                    }

                    if dos_guard.tokens > 0 {
                        dos_guard.tokens -= 1;
                        drop(dos_guard);

                        let actually_exists =
                            is_container_active_sync(&container_id, docker_socket_path);
                        if actually_exists {
                            let mut active_write = active_containers.write();
                            active_write.insert(container_id.clone());
                            is_valid = true;
                        } else {
                            let mut dos_write = anti_dos_state.lock();
                            if dos_write.negative_cache.len() >= crate::limiters::MAX_NEGATIVE_CACHE
                            {
                                if let Some(oldest) = dos_write.negative_queue.pop_front() {
                                    dos_write.negative_cache.remove(&oldest);
                                }
                            }
                            dos_write.negative_cache.insert(container_id.clone());
                            dos_write.negative_queue.push_back(container_id.clone());
                        }
                    } else {
                        drop(dos_guard);
                        emit_log(
                            "CRITICAL",
                            "orchestrator",
                            Some(rule_name),
                            Some(&container_id),
                            None,
                            Some("api_backpressure"),
                            "RECOURSE_ROUTED",
                            "Lookup token pool exhausted. Container identity unverified but threat signature matches. Enforcing fallback routing.",
                            config_log_level,
                            json_enabled,
                        );

                        let fallback_id = format!(
                            "UNSYNCED_ID_{}",
                            &container_id[..std::cmp::min(12, container_id.len())]
                        );
                        let mut active_try = try_act.clone();
                        if is_from_file && active_try.first() != Some(&AtomicAction::ValidateState)
                        {
                            active_try.insert(0, AtomicAction::ValidateState);
                        }

                        dispatch_to_worker(
                            registry,
                            fallback_id,
                            active_try,
                            final_act.clone(),
                            rule_name.clone(),
                            Arc::clone(whitelist),
                            Arc::clone(table),
                            json_enabled,
                            config_log_level,
                            docker_socket_path,
                            line.to_string(),
                            max_workers,
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
                config_log_level,
                docker_socket_path,
                line.to_string(),
                max_workers,
            );
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
    config_log_level: LogLevel,
    docker_socket_path: &str,
    trigger_message: String,
    max_workers: usize,
) {
    {
        let reg_read = registry.read();
        if let Some(tx) = reg_read.get(&container_id) {
            if let Err(e) = tx.try_send((try_actions, final_actions, rule_name, trigger_message)) {
                match e {
                    TrySendError::Full((_, _, rule, _)) => {
                        emit_log(
                            "CRITICAL",
                            "orchestrator",
                            Some(&rule),
                            Some(&container_id),
                            None,
                            Some("route"),
                            "FAST_PATH_DROPPED",
                            "Queue saturated on fast-path lookup. Enforcing rigid backpressure: Event dropped to prevent host OOM.",
                            config_log_level,
                            json_enabled,
                        );
                    }
                    TrySendError::Disconnected((_, _, rule, _)) => {
                        emit_log(
                            "CRITICAL",
                            "orchestrator",
                            Some(&rule),
                            Some(&container_id),
                            None,
                            Some("route"),
                            "FAST_PATH_BROKEN_PIPE",
                            "Catastrophic Failure: Fast-path ingestion channel disconnected. Worker thread has terminated unexpectedly!",
                            config_log_level,
                            json_enabled,
                        );
                    }
                }
            }
            return;
        }
    }

    let mut reg_write = registry.write();

    if !reg_write.contains_key(&container_id) && reg_write.len() >= max_workers {
        emit_log(
            "CRITICAL",
            "orchestrator",
            Some(&rule_name),
            Some(&container_id),
            None,
            Some("route"),
            "OOM_PREVENTION",
            "Maximum worker thread ceiling reached. Flood detected.",
            config_log_level,
            json_enabled,
        );
        return;
    }

    emit_log(
        "DEBUG",
        "orchestrator",
        Some(&rule_name),
        Some(&container_id),
        None,
        Some("route"),
        "DISPATCHED",
        "Incident response task successfully routed to specialized isolated worker context.",
        config_log_level,
        json_enabled,
    );

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
                config_log_level,
                ds_clone,
            );
        });

        worker_tx
    });

    let _ = tx.try_send((try_actions, final_actions, rule_name.clone(), trigger_message)).map_err(|e| {
        match e {
            TrySendError::Full(_) => {
                emit_log(
                    "CRITICAL", "orchestrator", Some(&rule_name), Some(&container_id), None, Some("route"), "SLOW_PATH_DROPPED",
                    "Worker execution queue full. Enforcing rigid backpressure: Event dropped to prevent host thread exhaustion.",
                    config_log_level, json_enabled
                );
            }
            TrySendError::Disconnected(_) => {
                emit_log(
                    "CRITICAL", "orchestrator", Some(&rule_name), Some(&container_id), None, Some("route"), "SLOW_PATH_BROKEN_PIPE",
                    "CRITICAL ERROR: Slow-path ingestion channel disconnected. Worker has ceased execution!",
                    config_log_level, json_enabled
                );
            }
        }
    });
}

fn run_worker_lifecycle(
    container_id: String,
    rx_chan: Receiver<WorkerChannelMessage>,
    registry: Arc<RwLock<RegistryMap>>,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    config_log_level: LogLevel,
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
                    config_log_level,
                    json_enabled,
                    rule,
                    docker_socket_path.clone(),
                    trigger_msg,
                );
            }
            Err(_) => {
                let mut reg = registry.write();
                match rx_chan.try_recv() {
                    Ok((try_cmds, final_cmds, rule, trigger_msg)) => {
                        drop(reg);
                        execute_containment_pipeline(
                            container_id.clone(),
                            try_cmds,
                            final_cmds,
                            Arc::clone(&whitelist),
                            Arc::clone(&table),
                            config_log_level,
                            json_enabled,
                            rule,
                            docker_socket_path.clone(),
                            trigger_msg,
                        );
                    }
                    _ => {
                        reg.remove(&container_id);
                        emit_log(
                            "TRACE",
                            "worker_lifecycle",
                            None,
                            Some(&container_id),
                            None,
                            Some("lifecycle_decay"),
                            "DECOMMISSIONED",
                            "Worker context inactive past 30s ceiling. Safely flushing channels and clearing footprints.",
                            config_log_level,
                            json_enabled,
                        );
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

pub fn notify_systemd_ready() {
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

pub fn compile_manifest_rules(
    rules: &[JsonRuleConfig],
    playbooks: &HashMap<String, PlaybookConfig>,
) -> Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)> {
    let mut compiled_list = Vec::new();

    for rule in rules {
        if let Some(playbook) = playbooks.get(&rule.playbook) {
            for pattern in &rule.match_any {
                if let Ok(rx) = Regex::new(pattern) {
                    compiled_list.push((
                        rule.name.clone(),
                        rx,
                        playbook.try_actions.clone(),
                        playbook.final_actions.clone(),
                    ));
                }
            }
        }
    }

    compiled_list
}

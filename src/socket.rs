// Ingestion Pipeline Socket Server
// Establishes trusted Unix Domain Socket environments, enforces SO_PEERCRED
// authentication boundaries, and parses real-time incoming container security streams.

use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mio::net::UnixListener as MioUnixListener;
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};

use crate::config::{AtomicAction, LogLevel, RegistryMap};
use crate::limiters::{AntiDosState, GlobalRateLimiter};
use crate::logger::emit_log;

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
fn get_peer_creds(stream: &std::os::unix::net::UnixStream) -> std::io::Result<(u32, i32)> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
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
        Ok((ucred.uid, ucred.pid))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn run_uds_server(
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<RwLock<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    config_log_level: LogLevel,
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashSet<String>>>,
    anti_dos_state: Arc<Mutex<AntiDosState>>,
    shutdown: Arc<AtomicBool>,
    max_workers: usize,
    global_limiter: Arc<GlobalRateLimiter>,
) {
    let socket_path = "/var/run/runsc-sentry-guard.sock";
    let _ = fs::remove_file(socket_path);

    let mut listener = match MioUnixListener::bind(socket_path) {
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
                config_log_level,
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
            config_log_level,
            json_enabled,
        );
        return;
    }

    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            emit_log(
                "ERROR",
                "uds_server",
                None,
                None,
                None,
                None,
                "CRASH",
                &format!("Failed to initialize mio Poll instance: {}", e),
                config_log_level,
                json_enabled,
            );
            return;
        }
    };

    const SERVER: Token = Token(0);
    if let Err(e) = poll.registry().register(&mut listener, SERVER, Interest::READABLE) {
        emit_log(
            "ERROR",
            "uds_server",
            None,
            None,
            None,
            None,
            "CRASH",
            &format!("Failed to register UDS listener with mio registry: {}", e),
            config_log_level,
            json_enabled,
        );
        return;
    }

    crate::ingestion::notify_systemd_ready();

    let active_connections = Arc::new(AtomicUsize::new(0));
    const MAX_UDS_CONNECTIONS: usize = 50;
    let mut events = Events::with_capacity(128);

    while !shutdown.load(Ordering::SeqCst) {
        if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(100))) {
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        for event in events.iter() {
            if event.token() == SERVER && event.is_readable() {
                loop {
                    match listener.accept() {
                        Ok((mio_stream, _)) => {
                            let stream = unsafe {
                                std::os::unix::net::UnixStream::from_raw_fd(
                                    mio_stream.into_raw_fd(),
                                )
                            };

                            if let Err(e) = stream.set_nonblocking(false) {
                                emit_log(
                                    "ERROR",
                                    "uds_server",
                                    None,
                                    None,
                                    None,
                                    None,
                                    "CRASH",
                                    &format!("Failed to set blocking mode: {}", e),
                                    config_log_level,
                                    json_enabled,
                                );
                                continue;
                            }

                            #[cfg(target_os = "linux")]
                            let socket_container_id = match get_peer_creds(&stream) {
                                Ok((peer_uid, peer_pid)) => {
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
                                            config_log_level,
                                            json_enabled,
                                        );
                                        continue;
                                    }

                                    let id = crate::worker::extract_id_from_pid(peer_pid);
                                    if id.is_none() {
                                        emit_log(
                                            "WARN",
                                            "uds_server",
                                            None,
                                            None,
                                            None,
                                            Some("trust_boundary"),
                                            "REJECTED",
                                            &format!("Failed to resolve container ID from peer PID {}. Connection dropped.", peer_pid),
                                            config_log_level,
                                            json_enabled,
                                        );
                                        continue;
                                    }
                                    id
                                }
                                Err(_) => continue,
                            };

                            #[cfg(not(target_os = "linux"))]
                            let socket_container_id: Option<String> = None;

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
                            let cid_socket_clone = socket_container_id.clone();
                            let limiter_clone = Arc::clone(&global_limiter);

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
                                    config_log_level,
                                    ds_path_clone,
                                    cache_clone,
                                    dos_clone,
                                    cid_socket_clone,
                                    max_workers,
                                    limiter_clone,
                                );
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}

fn handle_uds_stream(
    stream: std::os::unix::net::UnixStream,
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<RwLock<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    config_log_level: LogLevel,
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashSet<String>>>,
    anti_dos_state: Arc<Mutex<AntiDosState>>,
    socket_container_id: Option<String>,
    max_workers: usize,
    global_limiter: Arc<GlobalRateLimiter>,
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
            config_log_level,
            json_enabled,
        );
        return;
    }

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();

    loop {
        buf.clear();
        let mut chunk = reader.by_ref().take(8192);

        // Telemetry Hook: High-frequency frame parsing diagnostics gated under Trace noise channel
        emit_log(
            "TRACE",
            "uds_server",
            None,
            socket_container_id.as_deref(),
            None,
            Some("stream_read"),
            "PROCESSING",
            "Reading next raw diagnostic frame buffer partition across non-allocating socket channels.",
            config_log_level,
            json_enabled,
        );

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
                        config_log_level,
                        json_enabled,
                    );

                    let mut sink_buf = [0u8; 1024];
                    loop {
                        match reader.read(&mut sink_buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if sink_buf[..n].contains(&b'\n') {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    continue;
                }

                let current_line = String::from_utf8_lossy(&buf);
                let trimmed = current_line.trim_end();

                let rules_guard = regex_rules.read();
                crate::ingestion::evaluate_line_signatures(
                    trimmed,
                    &rules_guard,
                    &id_extractor,
                    &registry,
                    &whitelist,
                    &table,
                    json_enabled,
                    config_log_level,
                    &docker_socket_path,
                    socket_container_id.clone(),
                    false,
                    &active_containers,
                    &anti_dos_state,
                    max_workers,
                    &global_limiter,
                );
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uds_connection_guard_raii_lifecycles() {
        let counter = Arc::new(AtomicUsize::new(10));
        {
            let _guard = ConnectionGuard(Arc::clone(&counter));
            assert_eq!(counter.load(Ordering::SeqCst), 10);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn test_uds_connection_saturation_rejections() {
        let counter = Arc::new(AtomicUsize::new(0));
        const MAX_UDS_CONNECTIONS: usize = 50;
        let mut allocated_guards = Vec::new();

        for _ in 0..55 {
            if counter.load(Ordering::SeqCst) < MAX_UDS_CONNECTIONS {
                counter.fetch_add(1, Ordering::SeqCst);
                allocated_guards.push(ConnectionGuard(Arc::clone(&counter)));
            }
        }

        assert_eq!(counter.load(Ordering::SeqCst), 50);
        assert_eq!(allocated_guards.len(), 50);
    }
}
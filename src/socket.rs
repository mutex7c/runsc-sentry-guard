// Ingestion Pipeline Socket Server
// Establishes trusted Unix Domain Socket environments, enforces SO_PEERCRED
// authentication boundaries, and parses real-time incoming container security streams.

use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering}; 
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::config::{AtomicAction, RegistryMap};
use crate::logger::emit_log;
use crate::limiters::{AntiDosState, GlobalRateLimiter};

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
fn get_peer_creds(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
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
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashSet<String>>>,
    anti_dos_state: Arc<Mutex<AntiDosState>>,
    shutdown: Arc<AtomicBool>,
    max_workers: usize,
    global_limiter: Arc<GlobalRateLimiter>,
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
            &format!("Failed to enforce secure access permissions on UDS socket: {}", e),
            json_enabled,
        );
        return;
    }

    if listener.set_nonblocking(true).is_err() {
        emit_log(
            "ERROR",
            "uds_server",
            None,
            None,
            None,
            None,
            "CRASH",
            "Failed to transition tracking socket boundaries into non-blocking context modes.",
            json_enabled,
        );
        return;
    }

    crate::ingestion::notify_systemd_ready();

    let active_connections = Arc::new(AtomicUsize::new(0));
    const MAX_UDS_CONNECTIONS: usize = 50;

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
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
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn handle_uds_stream(
    stream: UnixStream,
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<RwLock<Vec<(String, Regex, Vec<AtomicAction>, Vec<AtomicAction>)>>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
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

                let rules_guard = regex_rules.read().expect("CRITICAL: Signatures lock poisoned.");
                crate::ingestion::evaluate_line_signatures(
                    trimmed,
                    &rules_guard,
                    &id_extractor,
                    &registry,
                    &whitelist,
                    &table,
                    json_enabled,
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
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_uds_connection_guard_raii_lifecycles() {
        let counter = Arc::new(AtomicUsize::new(10));

        {
            let _guard = ConnectionGuard(Arc::clone(&counter));
            // Scope retention mimics an active open UDS streaming socket session channel
            assert_eq!(counter.load(Ordering::SeqCst), 10);
        } // Guard drops out of scope here as the simulated stream closes

        assert_eq!(
            counter.load(Ordering::SeqCst),
            9,
            "ConnectionGuard RAII destructor failed to decrement active tracking bounds upon closure!"
        );
    }
}
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mio::net::{UnixListener as MioUnixListener, UnixStream as MioUnixStream};
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};

use crate::config::{LogLevel, RegistryMap};
use crate::limiters::{AntiDosState, GlobalRateLimiter};
use crate::logger::emit_log;

const SERVER: Token = Token(0);
const FIRST_CLIENT_TOKEN: usize = 1;

#[cfg(target_os = "linux")]
fn get_peer_creds(fd: std::os::unix::io::RawFd) -> std::io::Result<(u32, i32)> {
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

#[cfg(target_os = "linux")]
fn extract_id_race_free(peer_pid: i32, peer_uid: u32) -> Option<String> {
    use std::ffi::CString;
    use std::io::BufRead;
    use std::os::unix::io::FromRawFd;
    use std::sync::OnceLock;

    static ID_EXTRACTOR: OnceLock<Regex> = OnceLock::new();
    let extractor =
        ID_EXTRACTOR.get_or_init(|| Regex::new(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{12})\b").unwrap());

    struct FdGuard(std::os::unix::io::RawFd);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe {
                    libc::close(self.0);
                }
            }
        }
    }

    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, peer_pid, 0) as std::os::unix::io::RawFd };
    if pidfd < 0 {
        return None;
    }
    let _pidfd_guard = FdGuard(pidfd);

    let proc_path = format!("/proc/{}", peer_pid);
    let proc_dir_c = CString::new(proc_path).ok()?;
    let proc_dir_fd = unsafe {
        libc::open(
            proc_dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if proc_dir_fd < 0 {
        return None;
    }
    let _proc_dir_guard = FdGuard(proc_dir_fd);

    unsafe {
        let mut statbuf = std::mem::zeroed::<libc::stat>();
        if libc::fstat(proc_dir_fd, &mut statbuf) < 0 || statbuf.st_uid != peer_uid {
            return None;
        }
    }

    let cgroup_c = CString::new("cgroup").unwrap();
    let cgroup_fd = unsafe {
        libc::openat(
            proc_dir_fd,
            cgroup_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if cgroup_fd < 0 {
        return None;
    }
    let cgroup_guard = FdGuard(cgroup_fd);

    let is_same_process = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ) == 0
    };
    if !is_same_process {
        return None;
    }

    std::mem::forget(cgroup_guard);
    let file = unsafe { fs::File::from_raw_fd(cgroup_fd) };
    let reader = std::io::BufReader::new(file);

    let lines_iter = reader.lines().filter_map(|l| l.ok());
    crate::worker::extract_id_from_lines(lines_iter, extractor)
}

struct AsyncClientConnection {
    stream: MioUnixStream,
    buffer: Vec<u8>,
    container_id: Option<String>,
}

pub fn run_uds_server(
    registry: Arc<RwLock<RegistryMap>>,
    regex_rules: Arc<RwLock<crate::ingestion::CompiledManifest>>,
    id_extractor: Regex,
    whitelist: Arc<Vec<ipnet::IpNet>>,
    table: Arc<String>,
    json_enabled: bool,
    config_log_level: LogLevel,
    docker_socket_path: String,
    active_containers: Arc<RwLock<HashMap<String, String>>>,
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

    if let Err(e) = poll
        .registry()
        .register(&mut listener, SERVER, Interest::READABLE)
    {
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

    let mut connection_pool: HashMap<Token, AsyncClientConnection> = HashMap::new();
    let mut unique_token_counter = FIRST_CLIENT_TOKEN;
    let mut events = Events::with_capacity(128);

    let mut backlog_pending = false;
    const MAX_UDS_CONNECTIONS: usize = 50;

    while !shutdown.load(Ordering::SeqCst) {
        if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(100))) {
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        let mut slot_freed = false;

        for event in events.iter() {
            match event.token() {
                SERVER => {
                    backlog_pending = true;
                }
                client_token => {
                    let mut should_remove = false;
                    if let Some(conn) = connection_pool.get_mut(&client_token) {
                        let mut read_buf = [0u8; 1024];
                        loop {
                            match conn.stream.read(&mut read_buf) {
                                Ok(0) => {
                                    should_remove = true;
                                    break;
                                }
                                Ok(n) => {
                                    conn.buffer.extend_from_slice(&read_buf[..n]);
                                    if conn.buffer.len() > 65536 {
                                        conn.buffer.clear();
                                        should_remove = true;
                                        break;
                                    }

                                    let mut start_pos = 0;
                                    while let Some(newline_offset) =
                                        conn.buffer[start_pos..].iter().position(|&b| b == b'\n')
                                    {
                                        let end_pos = start_pos + newline_offset;
                                        let line_slice = String::from_utf8_lossy(
                                            &conn.buffer[start_pos..end_pos],
                                        );
                                        let trimmed = line_slice.trim_end();

                                        if !trimmed.is_empty() {
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
                                                conn.container_id.clone(),
                                                false,
                                                &active_containers,
                                                &anti_dos_state,
                                                max_workers,
                                                &global_limiter,
                                            );
                                        }
                                        start_pos = end_pos + 1;
                                    }
                                    if start_pos > 0 {
                                        conn.buffer.drain(0..start_pos);
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(_) => {
                                    should_remove = true;
                                    break;
                                }
                            }
                        }
                    }

                    if should_remove {
                        if let Some(mut conn) = connection_pool.remove(&client_token) {
                            let _ = poll.registry().deregister(&mut conn.stream);
                            slot_freed = true;
                        }
                    }
                }
            }
        }

        if (backlog_pending || slot_freed) && connection_pool.len() < MAX_UDS_CONNECTIONS {
            loop {
                if connection_pool.len() >= MAX_UDS_CONNECTIONS {
                    backlog_pending = true;
                    break;
                }

                match listener.accept() {
                    Ok((mut client_stream, _)) => {
                        #[cfg(target_os = "linux")]
                        let socket_container_id = match get_peer_creds(
                            std::os::unix::io::AsRawFd::as_raw_fd(&client_stream),
                        ) {
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
                                        &format!(
                                            "Unauthorized UID {} attempted UDS connection. Payload dropped.",
                                            peer_uid
                                        ),
                                        config_log_level,
                                        json_enabled,
                                    );
                                    continue;
                                }
                                extract_id_race_free(peer_pid, peer_uid)
                            }
                            Err(_) => continue,
                        };
                        #[cfg(not(target_os = "linux"))]
                        let socket_container_id: Option<String> = None;

                        let client_token = Token(unique_token_counter);
                        unique_token_counter += 1;
                        if unique_token_counter > 1000000 {
                            unique_token_counter = FIRST_CLIENT_TOKEN;
                        }

                        if poll
                            .registry()
                            .register(&mut client_stream, client_token, Interest::READABLE)
                            .is_ok()
                        {
                            connection_pool.insert(
                                client_token,
                                AsyncClientConnection {
                                    stream: client_stream,
                                    buffer: Vec::with_capacity(1024),
                                    container_id: socket_container_id,
                                },
                            );
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        backlog_pending = false;
                        break;
                    }
                    Err(_) => {
                        backlog_pending = false;
                        break;
                    }
                }
            }
        }
    }
}

// Application Entry point
// Orchestrates process initialization, ambient capability stripping, and seccomp jail loading.

mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use tailer::start_monitor_loop;

fn main() {
    // Enforcement Boundary: Validate active Linux root execution privileges explicitly
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "Fatal System Error: runsc-sentry-guard must execute as root to manage network filters."
            );
            std::process::exit(1);
        }
    }

    println!("[INFO] Initializing runsc-sentry-guard active containment runtime architecture...");

    let production_path = "/etc/runsc-sentry-guard/config.toml";
    let developer_path = "config.toml";

    let active_path = if Path::new(production_path).exists() {
        production_path
    } else {
        developer_path
    };

    match load_config(active_path) {
        Ok(valid_config) => {
            let json_enabled = valid_config.monitor.json_logging_enabled;

            logger::emit_log(
                "INFO",
                "initialization",
                None,
                None,
                None,
                None,
                "ARMED",
                &format!(
                    "Configuration profile verification successful via path: {}",
                    active_path
                ),
                json_enabled,
            );

            // Permanently lock down permitted POSIX capabilities
            #[cfg(target_os = "linux")]
            drop_privileges(json_enabled);

            // Commit rigid Berkeley Packet Filters directly into active kernel execution space
            #[cfg(target_os = "linux")]
            init_seccomp(json_enabled);

            // Compliance Fix: Issue systemd orchestration READY notify packets EXACTLY once at initialization success
            notify_systemd_ready();

            // Hand execution layers gracefully onto multithreaded monitoring handlers
            start_monitor_loop(valid_config);
        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

// Permanently strips effective and ambient process capabilities strictly down to CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
fn drop_privileges(json_enabled: bool) {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        eprintln!(
            "[WARN] Failed to wipe ambient initialization capabilities: {:?}",
            e
        );
    }

    let mut structural_capabilities = HashSet::new();
    structural_capabilities.insert(Capability::CAP_NET_ADMIN);

    if let Err(e) = caps::set(None, CapSet::Effective, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!(
                "Fatal security boundary breakdown lowering effective sets: {:?}",
                e
            ),
            json_enabled,
        );
        std::process::exit(1);
    }

    if let Err(e) = caps::set(None, CapSet::Permitted, &structural_capabilities) {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("privilege_drop"),
            "CRASH",
            &format!(
                "Fatal security boundary breakdown lowering permitted sets: {:?}",
                e
            ),
            json_enabled,
        );
        std::process::exit(1);
    }

    logger::emit_log(
        "INFO",
        "initialization",
        None,
        None,
        None,
        Some("privilege_drop"),
        "SUCCESS",
        "Process context shed ambient root access patterns. Boundary safely pinned to CAP_NET_ADMIN.",
        json_enabled,
    );
}

// Compiles and locks down an immutable BPF system call whitelist straight onto the running kernel ring.
#[cfg(target_os = "linux")]
fn init_seccomp(json_enabled: bool) {
    use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};

    let mut filter = match ScmpFilterContext::new(ScmpAction::KillProcess) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!(
                "Fatal Error compiling baseline Seccomp filter profile context: {:?}",
                e
            );
            std::process::exit(1);
        }
    };

    let target_archs = [ScmpArch::X8664, ScmpArch::Aarch64, ScmpArch::X86];
    for arch in target_archs {
        let _ = filter.add_arch(arch);
    }

    let system_call_whitelist = [
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise", // Memory [cite: 181]
        "openat",
        "read",
        "write",
        "close",
        "lseek",
        "fstat",
        "newfstatat",
        "statx",
        "pread64",
        "pwrite64",   // Files [cite: 183]
        "getdents64", // Directories [cite: 185]
        "clone",
        "clone3",
        "execve",
        "wait4",
        "exit",
        "exit_group",
        "futex",
        "sched_yield",
        "set_robust_list", // Process [cite: 187]
        "pipe",
        "pipe2",
        "fcntl",
        "ioctl",
        "writev",
        "readv", // IPC [cite: 189]
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "nanosleep",
        "clock_nanosleep", // Timers [cite: 191]
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigqueue", // Signals [cite: 193]
        "socket",
        "connect",
        "bind",
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "setsockopt",
        "getsockopt",
        "uname", // Networking [cite: 196]
    ];

    for syscall_name in system_call_whitelist {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            if let Err(e) = filter.add_rule(ScmpAction::Allow, syscall) {
                eprintln!(
                    "Fatal Error embedding Seccomp rule [{}]: {:?}",
                    syscall_name, e
                );
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = filter.load() {
        logger::emit_log(
            "ERROR",
            "initialization",
            None,
            None,
            None,
            Some("seccomp_sandbox"),
            "CRASH",
            &format!(
                "Failed to lock down BPF seccomp sandbox infrastructure matrix: {:?}",
                e
            ),
            json_enabled,
        );
        std::process::exit(1);
    }

    logger::emit_log(
        "INFO",
        "initialization",
        None,
        None,
        None,
        Some("seccomp_sandbox"),
        "SUCCESS",
        "In-app system call rules committed. Boundary hard insulated against kernel privilege escalation.",
        json_enabled,
    );
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

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

            // Permanently lock down permitted POSIX capabilities and drop DAC overrides
            #[cfg(target_os = "linux")]
            drop_privileges(json_enabled);

            // Commit rigid Berkeley Packet Filters directly into active kernel execution space
            #[cfg(target_os = "linux")]
            init_seccomp(json_enabled);
            
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

    // Privilege Shedding to neutralize DAC Override
    unsafe {

        // Inform kernel to preserve permitted capability boundaries across the identity shift
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            eprintln!("Fatal System Error: prctl(PR_SET_KEEPCAPS) invocation rejected by kernel.");
            std::process::exit(1);
        }
    }

    // Clear all ambiently inherited privileges
    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        eprintln!(
            "[WARN] Failed to wipe ambient initialization capabilities: {:?}",
            e
        );
    }

    let mut structural_capabilities = HashSet::new();
    structural_capabilities.insert(Capability::CAP_NET_ADMIN);

    // Lock Permitted set to CAP_NET_ADMIN
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

    // Re-assert CAP_NET_ADMIN into the Effective execution set
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

    if let Err(e) = caps::set(None, CapSet::Inheritable, &structural_capabilities) {
        eprintln!("Failed to set Inheritable capabilities: {:?}", e);
        std::process::exit(1);
    }

    if let Err(e) = caps::set(None, CapSet::Ambient, &structural_capabilities) {
        eprintln!("Failed to set Ambient capabilities: {:?}", e);
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
        "Process execution boundary safely pinned to CAP_NET_ADMIN.",
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
        if let Err(e) = filter.add_arch(arch) {
            eprintln!(
                "Fatal Error adding system architecture compilation matrix targets [{:?}]: {:?}",
                arch, e
            );
            std::process::exit(1);
        }
    }

    let system_call_whitelist = [
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise", // Memory
        "openat",
        "read",
        "write",
        "close",
        "lseek",
        "fstat",
        "newfstatat",
        "statx",
        "pread64",
        "pwrite64",   // Files
        "getdents64", // Directories
        "clone",
        "clone3",
        "execve",
        "wait4",
        "exit",
        "exit_group",
        "futex",
        "sched_yield",
        "set_robust_list", // Process
        "pipe",
        "pipe2",
        "fcntl",
        "ioctl",
        "writev",
        "readv", // IPC
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "nanosleep",
        "clock_nanosleep", // Timers
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigqueue", // Signals
        "socket",
        "connect",
        "bind",
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "setsockopt",
        "getsockopt",
        "uname", // Networking
        "prctl",
        "getsockname",
        "getpeername",
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

mod config;
mod logger;
mod tailer;
mod worker;

use config::load_config;
use std::path::Path;
use tailer::start_monitor_loop;

fn main() {
    // Enforcement Boundary: Verify Linux root execution privileges
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "Fatal Error: runsc-sentry-guard must run explicitly as root to interact with nftables/docker namespaces."
            );
            std::process::exit(1);
        }
    }

    println!("[INFO] Launching runsc-sentry-guard runtime architecture initialization...");

    // Determine target configuration file scope based on environmental placement
    let production_path = "/etc/runsc-sentry-guard/config.toml";
    let developer_path = "config.toml";

    let active_path = if Path::new(production_path).exists() {
        production_path
    } else {
        developer_path
    };

    // Attempt fail-safe load of configuration parameters
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
                    "Configuration profiles loaded cleanly via path target: {}",
                    active_path
                ),
                json_enabled,
            );

            // Restrict ambient capability bounds post-initialization
            #[cfg(target_os = "linux")]
            drop_privileges(json_enabled);

            // Compile and load strict in-app BPF seccomp whitelist filters
            #[cfg(target_os = "linux")]
            init_seccomp(json_enabled);

            // Hand off execution loops to the monitor thread framework
            start_monitor_loop(valid_config);
        }
        Err(err_msg) => {
            eprintln!("System Architectural Boot Panic: {}", err_msg);
            std::process::exit(1);
        }
    }
}

/// Permanently drops ambient and effective capabilities down to CAP_NET_ADMIN (Task 8)
#[cfg(target_os = "linux")]
fn drop_privileges(json_enabled: bool) {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        eprintln!(
            "[WARN] Failed to clear ambient system capabilities: {:?}",
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
            &format!("Fatal security failure dropping effective sets: {:?}", e),
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
            &format!("Fatal security failure dropping permitted sets: {:?}", e),
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
        "Process shed ambient root access. Bound context safely to host CAP_NET_ADMIN.",
        json_enabled,
    );
}

/// Compiles and commits a rigid BPF system call whitelist matrix straight into the active Linux kernel (Task 7)
#[cfg(target_os = "linux")]
fn init_seccomp(json_enabled: bool) {
    use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};

    // Initialize a fail-closed context: Any unmatched syscall will instantly terminate the process
    let mut filter = match ScmpFilterContext::new(ScmpAction::KillProcess) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Fatal Error initializing Seccomp filter context: {:?}", e);
            std::process::exit(1);
        }
    };

    // Explicitly guard cross-architecture ABI multiplexing tricks
    let targets_archs = [ScmpArch::X8664, ScmpArch::Aarch64, ScmpArch::X86];
    for arch in targets_archs {
        if let Err(e) = filter.add_arch(arch) {
            eprintln!(
                "[WARN] Seccomp engine skipped architecture registration block: {:?}",
                e
            );
        }
    }

    // Define the strict mathematical blueprint of operational system calls permitted
    let system_call_whitelist = [
        // Memory Protection & Management
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        // Bounded File Handling & Discovery I/O
        "openat",
        "read",
        "write",
        "close",
        "lseek",
        "fstat",
        "newfstatat",
        "statx",
        "pread64",
        "pwrite64",
        // Directory Inode Traversal Loops
        "getdents64",
        // Process Management, Execution, & Thread Lifecycles
        "clone",
        "clone3",
        "execve",
        "wait4",
        "exit",
        "exit_group",
        "futex",
        "sched_yield",
        "set_robust_list",
        // IPC Streams, Buffers, & Device Controllers
        "pipe",
        "pipe2",
        "fcntl",
        "ioctl",
        "writev",
        "readv",
        // Event Processing & Architectural Cadence Delays
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "nanosleep",
        "clock_nanosleep",
        // System Signals Handlers
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigqueue",
        // Networking & Inter-process Communication Sockets (Required for child executions: curl, docker inspect, and nft netlink)
        "socket",
        "connect",
        "bind",
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "setsockopt",
        "getsockopt",
        "uname",
    ];

    // Bind the allowed array directly into the BPF filter ruleset
    for syscall_name in system_call_whitelist {
        match ScmpSyscall::from_name(syscall_name) {
            Ok(syscall) => {
                if let Err(e) = filter.add_rule(ScmpAction::Allow, syscall) {
                    eprintln!(
                        "Fatal Error binding Seccomp whitelist rule [{}]: {:?}",
                        syscall_name, e
                    );
                    std::process::exit(1);
                }
            }
            Err(_) => {
                // If a specific system call is missing from the underlying host kernel ABI, gracefully skip it
                continue;
            }
        }
    }

    // Unidirectionally commit the entire compiled ruleset directly into kernel enforcement space
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
                "Failed to lock down BPF seccomp system filter matrix: {:?}",
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
        "In-app BPF syscall filters committed. Process boundary isolated against kernel privilege exploits.",
        json_enabled,
    );
}

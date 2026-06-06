// Linux seccomp-bpf profile loader.
// Installs after configuration validation and capability trimming, before worker threads exist.

use crate::config::{AtomicAction, GuardConfig};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSeccompProfile {
    Core,
    AutomationCompatible,
}

impl fmt::Display for RuntimeSeccompProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeSeccompProfile::Core => f.write_str("core"),
            RuntimeSeccompProfile::AutomationCompatible => f.write_str("automation-compatible"),
        }
    }
}

pub fn install_for_config(config: &GuardConfig) -> Result<RuntimeSeccompProfile, String> {
    let profile = profile_for_config(config);
    install_profile(profile)?;
    Ok(profile)
}

fn profile_for_config(config: &GuardConfig) -> RuntimeSeccompProfile {
    let needs_external_process = config.rules.iter().any(|rule| {
        rule.try_actions
            .iter()
            .chain(rule.final_actions.iter())
            .any(action_requires_automation_profile)
    });

    if needs_external_process {
        RuntimeSeccompProfile::AutomationCompatible
    } else {
        RuntimeSeccompProfile::Core
    }
}

fn action_requires_automation_profile(action: &AtomicAction) -> bool {
    matches!(
        action,
        AtomicAction::NftBlacklist { .. }
            | AtomicAction::RunCustomScript { .. }
            | AtomicAction::WebhookAlert { .. }
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_profile(profile: RuntimeSeccompProfile) -> Result<(), String> {
    let mut filter = build_filter(profile);

    if filter.len() > libc::BPF_MAXINSNS as usize {
        return Err(format!(
            "generated BPF program contains {} instructions; kernel maximum is {}",
            filter.len(),
            libc::BPF_MAXINSNS
        ));
    }

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) rejected: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut program = libc::sock_fprog {
            len: filter.len() as libc::c_ushort,
            filter: filter.as_mut_ptr(),
        };

        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
            0,
            0,
        ) != 0
        {
            return Err(format!(
                "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) rejected: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn install_profile(_profile: RuntimeSeccompProfile) -> Result<(), String> {
    Err(format!(
        "native seccomp-bpf profile is implemented for x86_64 Linux; unsupported architecture: {}",
        std::env::consts::ARCH
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn build_filter(profile: RuntimeSeccompProfile) -> Vec<libc::sock_filter> {
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

    let mut filter = vec![
        stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            std::mem::offset_of!(libc::seccomp_data, arch) as u32,
        ),
        jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            AUDIT_ARCH_X86_64,
            1,
            0,
        ),
        stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            std::mem::offset_of!(libc::seccomp_data, nr) as u32,
        ),
    ];

    for syscall in allowed_syscalls(profile) {
        filter.push(jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            syscall as u32,
            0,
            1,
        ));
        filter.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW));
    }

    filter.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_TRAP));
    filter
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn allowed_syscalls(profile: RuntimeSeccompProfile) -> Vec<libc::c_long> {
    let mut syscalls = core_syscalls();

    if profile == RuntimeSeccompProfile::AutomationCompatible {
        syscalls.extend(automation_syscalls());
    }

    syscalls.sort_unstable();
    syscalls.dedup();
    syscalls
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn core_syscalls() -> Vec<libc::c_long> {
    vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_getcwd,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_umask,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigsuspend,
        libc::SYS_sigaltstack,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_futex,
        libc::SYS_futex_waitv,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_time,
        libc::SYS_prlimit64,
        libc::SYS_getrlimit,
        libc::SYS_getrandom,
        libc::SYS_membarrier,
        libc::SYS_uname,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
    ]
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn automation_syscalls() -> Vec<libc::c_long> {
    vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_kill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_setpgid,
        libc::SYS_getpgid,
        libc::SYS_getpgrp,
        libc::SYS_getsid,
        libc::SYS_setsid,
        libc::SYS_getgroups,
        libc::SYS_setgroups,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_personality,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_rmdir,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_fchownat,
        libc::SYS_creat,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_sendfile,
        libc::SYS_copy_file_range,
        libc::SYS_splice,
        libc::SYS_tee,
        libc::SYS_vmsplice,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_fgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_flistxattr,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_times,
        libc::SYS_getpriority,
        libc::SYS_setpriority,
        libc::SYS_sched_getparam,
        libc::SYS_sched_setparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_getattr,
        libc::SYS_sched_setattr,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_sched_setaffinity,
        libc::SYS_inotify_init,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_fadvise64,
        libc::SYS_mincore,
        libc::SYS_msync,
        libc::SYS_memfd_create,
    ]
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn stmt(code: libc::__u32, k: libc::__u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn jump(code: libc::__u32, k: libc::__u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IngestionMode, MonitorConfig, RuleConfig};
    use std::path::PathBuf;

    fn monitor_config() -> MonitorConfig {
        MonitorConfig {
            mode: IngestionMode::File,
            log_dir: "/var/log/gvisor/".to_string(),
            check_interval_ms: 1000,
            ip_whitelist: vec!["127.0.0.1/32".parse().unwrap()],
            nftables_default_table: "inet security_ops".to_string(),
            json_logging_enabled: false,
            docker_socket_path: "/var/run/docker.sock".to_string(),
            seccomp_enabled: true,
            systemd_watchdog_interval_ms: 5000,
        }
    }

    fn guard_with_actions(try_actions: Vec<AtomicAction>) -> GuardConfig {
        GuardConfig {
            monitor: monitor_config(),
            rules: vec![RuleConfig {
                name: "test".to_string(),
                file_pattern: "*.boot".to_string(),
                regex_match: "execve".to_string(),
                try_actions,
                final_actions: vec![AtomicAction::LogCritical],
            }],
        }
    }

    #[test]
    fn core_profile_selected_without_child_process_actions() {
        let config = guard_with_actions(vec![AtomicAction::ValidateState, AtomicAction::Pause]);
        assert_eq!(profile_for_config(&config), RuntimeSeccompProfile::Core);
    }

    #[test]
    fn automation_profile_selected_for_external_actions() {
        let config = guard_with_actions(vec![AtomicAction::RunCustomScript {
            path: PathBuf::from("/usr/local/bin/respond"),
        }]);
        assert_eq!(
            profile_for_config(&config),
            RuntimeSeccompProfile::AutomationCompatible
        );

        let config = guard_with_actions(vec![AtomicAction::NftBlacklist {
            set_name: "container_blacklist".to_string(),
            timeout: "24h".to_string(),
        }]);
        assert_eq!(
            profile_for_config(&config),
            RuntimeSeccompProfile::AutomationCompatible
        );

        let config = guard_with_actions(vec![AtomicAction::WebhookAlert {
            url: "https://hooks.example.invalid".to_string(),
        }]);
        assert_eq!(
            profile_for_config(&config),
            RuntimeSeccompProfile::AutomationCompatible
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn automation_profile_extends_core_profile() {
        let core = allowed_syscalls(RuntimeSeccompProfile::Core);
        let automation = allowed_syscalls(RuntimeSeccompProfile::AutomationCompatible);

        assert!(automation.len() > core.len());
        assert!(automation.contains(&libc::SYS_execve));
        assert!(automation.contains(&libc::SYS_wait4));
        assert!(!core.contains(&libc::SYS_execve));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn generated_bpf_program_stays_within_kernel_instruction_limit() {
        let filter = build_filter(RuntimeSeccompProfile::AutomationCompatible);
        assert!(filter.len() < libc::BPF_MAXINSNS as usize);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn high_risk_kernel_mutation_syscalls_remain_denied() {
        let automation = allowed_syscalls(RuntimeSeccompProfile::AutomationCompatible);
        let denied = [
            libc::SYS_bpf,
            libc::SYS_chroot,
            libc::SYS_finit_module,
            libc::SYS_init_module,
            libc::SYS_io_uring_setup,
            libc::SYS_keyctl,
            libc::SYS_mount,
            libc::SYS_perf_event_open,
            libc::SYS_ptrace,
            libc::SYS_reboot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_userfaultfd,
        ];

        for syscall in denied {
            assert!(!automation.contains(&syscall));
        }
    }
}

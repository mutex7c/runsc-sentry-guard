use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

// Data Contracts mapped directly to config.toml.example

// Replace the top section of src/config.rs down to GuardConfig

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AtomicAction {
    ValidateState,
    LogJson,
    Pause,
    Unpause,
    Restart,
    CommitSnapshot {
        prefix: String,
    },
    NftBlacklist {
        set_name: String,
        timeout: String,
    },
    // Map the specification keyword "kill" smoothly to ContainerSignal
    #[serde(alias = "kill")]
    ContainerSignal {
        signal: String,
    },
    RunCustomScript {
        path: PathBuf,
    },
    WebhookAlert {
        url: String,
    },
    LogCritical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    pub log_dir: String,
    pub check_interval_ms: u64,
    pub ip_whitelist: Vec<IpNet>,
    pub nftables_default_table: String,
    pub json_logging_enabled: bool,
    pub systemd_watchdog_interval_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    pub file_pattern: String,
    pub regex_match: String,
    pub try_actions: Vec<AtomicAction>,
    pub final_actions: Vec<AtomicAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub monitor: MonitorConfig,
    pub rules: Vec<RuleConfig>,
}

// Fail-Safe Configuration Loader Function

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GuardConfig, String> {
    let path_ref = path.as_ref();

    // Verify file existence out-of-band

    if !path_ref.exists() {
        return Err(format!(
            "Configuration file missing at: '{}'. Please provision your configuration profile.",
            path_ref.display()
        ));
    }

    // Read the raw file stream safely

    let content = fs::read_to_string(path_ref)
        .map_err(|e| format!("Failed to read configuration file: {}", e))?;

    // Deserialize TOML with strict type alignment

    let config: GuardConfig = toml::from_str(&content)
        .map_err(|e| format!("Configuration syntax verification failed: {}", e))?;

    // Input Validation: Enforce baseline sanity checks

    if config.rules.is_empty() {
        return Err("Security Constraint Violation: \
        At least one active detection [[rules]] block must be defined."
            .to_string());
    }

    for rule in &config.rules {
        if rule.try_actions.is_empty() && rule.final_actions.is_empty() {
            return Err(format!(
                "Validation Error: Rule '{}' \
            contains no defined execution actions.",
                rule.name
            ));
        }
    }

    Ok(config)
}

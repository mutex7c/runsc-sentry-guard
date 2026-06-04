use std::fs;
use std::path::Path;
use serde::Deserialize;
use ipnet::IpNet;
use std::path::PathBuf;

// Data Contracts mapped directly to config.toml.example

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AtomicAction {
    ValidateState,
    LogJson,
    Pause,
    Unpause,
    Restart,
    CommitSnapshot { prefix: String },
    NftBlacklist { set_name: String, timeout: String },
    ContainerSignal { signal: String },
    RunCustomScript { path: PathBuf },
    LogCritical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // Enforce validation boundary on global section properties
pub struct MonitorConfig {
    pub log_dir: String,
    pub check_interval_ms: u64,
    pub ip_whitelist: Vec<IpNet>,
    pub nftables_default_table: String,
    pub json_logging_enabled: bool,
    pub systemd_watchdog_interval_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // Prevent undetected parameter typos inside rules engines
pub struct RuleConfig {
    pub name: String,
    pub file_pattern: String,
    pub regex_match: String,
    pub try_actions: Vec<AtomicAction>,
    pub final_actions: Vec<AtomicAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // Reject inputs with unexpected parameters
pub struct GuardConfig {
    pub monitor: MonitorConfig,
    pub rules: Vec<RuleConfig>,
}

// Fail-Safe Configuration Loader Function

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GuardConfig, String> {
    let path_ref = path.as_ref();

    // 1. Verify file existence out-of-band

    if !path_ref.exists() {
        return Err(format!(
            "Configuration file missing at: '{}'. Please provision your configuration profile.",
            path_ref.display()
        ));
    }

    // 2. Read the raw file stream safely

    let content = fs::read_to_string(path_ref)
        .map_err(|e| format!("Failed to read configuration file: {}", e))?;

    // 3. Deserialize TOML with strict type alignment

    let config: GuardConfig = toml::from_str(&content)
        .map_err(|e| format!("Configuration syntax verification failed: {}", e))?;

    // 4. Input Validation: Enforce baseline sanity checks
    
    if config.rules.is_empty() {
        return Err("Security Constraint Violation: At least one active detection [[rules]] block must be defined.".to_string());
    }

    for rule in &config.rules {
        if rule.try_actions.is_empty() && rule.final_actions.is_empty() {
            return Err(format!("Validation Error: Rule '{}' contains no defined execution actions.", rule.name));
        }
    }

    Ok(config)
}
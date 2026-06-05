// Configuration Engine Module
// Handles the secure ingestion, parsing, and type-safe validation of the declarative `config.toml` structure.
// Enforces strict schema validations via Serde to ensure safe startup aborts on anomaly detection.

use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

// Strongly typed operational matrix definitions mapping onto specific automated containment actions.
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

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IngestionMode {
    File,
    Socket,
    Dual,
}

// Global Daemon Engine Metric Parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    pub mode: IngestionMode,
    pub log_dir: String,
    pub check_interval_ms: u64,
    pub ip_whitelist: Vec<IpNet>,
    pub nftables_default_table: String,
    pub json_logging_enabled: bool,
    /// Preserved for explicit systemd watchdog configuration parity in schema deployments
    #[allow(dead_code)]
    pub systemd_watchdog_interval_ms: u64,
}

// Threat Identification Rules Mapping Signatures to Incident Containment Playbooks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    // Preserved to support declarative glob patterns in infrastructure manifests
    #[allow(dead_code)]
    pub file_pattern: String,
    pub regex_match: String,
    pub try_actions: Vec<AtomicAction>,
    pub final_actions: Vec<AtomicAction>,
}

// Root Node Structure for the Entire Configuration Manifest Mapping.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub monitor: MonitorConfig,
    pub rules: Vec<RuleConfig>,
}

// Fail-Safe Configuration Loader
// Securely reads the raw profile manifest from the host system, executing deep structural syntax validations.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GuardConfig, String> {
    let path_ref = path.as_ref();

    if !path_ref.exists() {
        return Err(format!(
            "Configuration file missing at: '{}'. System initialization aborted safely.",
            path_ref.display()
        ));
    }

    let content = fs::read_to_string(path_ref)
        .map_err(|e| format!("Failed to read configuration file payload: {}", e))?;

    let config: GuardConfig = toml::from_str(&content)
        .map_err(|e| format!("Configuration structural verification failed: {}", e))?;

    if config.rules.is_empty() {
        return Err("Security Constraint Violation: At least one active detection [[rules]] block must be defined.".to_string());
    }

    for rule in &config.rules {
        if rule.try_actions.is_empty() && rule.final_actions.is_empty() {
            return Err(format!(
                "Validation Error: Rule '{}' contains no operational try/final actions.",
                rule.name
            ));
        }
    }

    Ok(config)
}

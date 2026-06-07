// Configuration Engine Module
// Handles the secure ingestion, parsing, and type-safe validation of the declarative `config.toml` structure.
// Enforces strict schema validations via Serde to ensure safe startup aborts on anomaly detection.

use anyhow::{anyhow, Context, Result};
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
    pub docker_socket_path: String,
    // FIX: Removed dead_code allowance; property is now actively consumed by the dedicated heartbeat thread.
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
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GuardConfig> {
    let path_ref = path.as_ref();

    let content = fs::read_to_string(path_ref).with_context(|| {
        format!(
            "Configuration missing, inaccessible, or tampered at '{}'",
            path_ref.display()
        )
    })?;

    let config: GuardConfig = toml::from_str(&content)
        .context("Configuration structural verification failed")?;

    if config.rules.is_empty() {
        return Err(anyhow!("Security Constraint Violation: At least one active detection [[rules]] block must be defined."));
    }

    for rule in &config.rules {
        if rule.try_actions.is_empty() && rule.final_actions.is_empty() {
            return Err(anyhow!(
                "Validation Error: Rule '{}' contains no operational try/final actions.",
                rule.name
            ));
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_load_config_valid_atomic_read() {
        let mut temp_path = env::temp_dir();
        temp_path.push("runsc_valid_test_config.toml");

        let mut file = File::create(&temp_path).unwrap();
        let toml_data = r#"
            [monitor]
            mode = "file"
            log_dir = "/var/log/gvisor/"
            check_interval_ms = 1000
            ip_whitelist = ["127.0.0.1/32"]
            nftables_default_table = "inet filter"
            json_logging_enabled = true
            docker_socket_path = "/var/run/docker.sock"
            systemd_watchdog_interval_ms = 5000

            [[rules]]
            name = "test_rule"
            file_pattern = "*.boot"
            regex_match = "malicious_string"
            try_actions = [{ type = "pause" }]
            final_actions = [{ type = "log_critical" }]
        "#;
        file.write_all(toml_data.as_bytes()).unwrap();

        let config = load_config(&temp_path).expect("Failed to parse valid configuration");

        assert_eq!(config.monitor.mode, IngestionMode::File);
        assert_eq!(config.monitor.docker_socket_path, "/var/run/docker.sock");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "test_rule");

        fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn test_load_config_missing_file_handling() {
        let result = load_config("/path/that/absolutely/does/not/exist/config.toml");
        assert!(result.is_err());

        // Extract the error and convert it to a string to verify the context
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Configuration missing, inaccessible, or tampered"));
    }
}
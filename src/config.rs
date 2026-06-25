use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

fn default_max_workers() -> usize {
    100
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    pub mode: IngestionMode,
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,
    pub log_dir: String,
    pub check_interval_ms: u64,
    pub ip_whitelist: Vec<IpNet>,
    pub nftables_default_table: String,
    pub json_logging_enabled: bool,
    pub docker_socket_path: String,
    pub systemd_watchdog_interval_ms: u64,
    pub flush_firewall_on_shutdown: bool,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    pub security_manifest_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub monitor: MonitorConfig,
}

#[derive(Debug, Deserialize)]
pub struct SecurityManifest {
    #[serde(default)]
    pub playbooks: HashMap<String, PlaybookConfig>,
    #[serde(default)]
    pub rules: Vec<JsonRuleConfig>,
    #[serde(default)]
    pub whitelists: Vec<WhitelistConfig>,
    #[serde(default)]
    pub mappings: HashMap<String, MappingConfig>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct PlaybookConfig {
    pub try_actions: Vec<AtomicAction>,
    pub final_actions: Vec<AtomicAction>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonRuleConfig {
    pub name: String,
    pub match_any: Vec<String>,
    pub playbook: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WhitelistConfig {
    pub name: String,
    pub match_any: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MappingConfig {
    #[serde(default)]
    pub active_rules: Vec<String>,
    #[serde(default)]
    pub active_whitelists: Vec<String>,
}

impl MappingConfig {
    pub fn contains_signature(&self, identity_name: &str, is_whitelist: bool) -> bool {
        if is_whitelist {
            self.active_whitelists
                .iter()
                .any(|name| name == identity_name)
        } else {
            self.active_rules.iter().any(|name| name == identity_name)
        }
    }
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GuardConfig> {
    let path_ref = path.as_ref();
    let content = fs::read_to_string(path_ref).with_context(|| {
        format!(
            "Configuration missing, inaccessible, or tampered at '{}'",
            path_ref.display()
        )
    })?;
    let config: GuardConfig =
        toml::from_str(&content).context("Configuration structural verification failed")?;
    Ok(config)
}

pub fn load_and_merge_manifests(
    paths: &[PathBuf],
) -> Result<(
    HashMap<String, PlaybookConfig>,
    Vec<JsonRuleConfig>,
    Vec<WhitelistConfig>,
    HashMap<String, MappingConfig>,
)> {
    let mut global_playbooks: HashMap<String, PlaybookConfig> = HashMap::new();
    let mut global_rules: Vec<JsonRuleConfig> = Vec::new();
    let mut global_whitelists: Vec<WhitelistConfig> = Vec::new();
    let mut global_mappings: HashMap<String, MappingConfig> = HashMap::new();

    let mut seen_rule_names: HashSet<String> = HashSet::new();
    let mut seen_whitelist_names: HashSet<String> = HashSet::new();

    for path in paths {
        let content = fs::read_to_string(path).with_context(|| {
            format!(
                "Failed to read security manifest file: '{}'",
                path.display()
            )
        })?;
        let manifest: SecurityManifest = serde_json::from_str(&content).with_context(|| {
            format!(
                "JSON schema structural verification failed for file: '{}'",
                path.display()
            )
        })?;

        for (name, playbook) in manifest.playbooks {
            if global_playbooks.contains_key(&name) {
                return Err(anyhow!(
                    "Configuration Collision Error: Playbook name '{}' found in '{}' conflicts with an existing playbook declaration.",
                    name,
                    path.display()
                ));
            }
            global_playbooks.insert(name, playbook);
        }

        for rule in manifest.rules {
            if seen_rule_names.contains(&rule.name) {
                return Err(anyhow!(
                    "Configuration Collision Error: Rule name '{}' defined in '{}' conflicts with an existing rule declaration.",
                    rule.name,
                    path.display()
                ));
            }
            seen_rule_names.insert(rule.name.clone());
            global_rules.push(rule);
        }

        for wl in manifest.whitelists {
            if seen_whitelist_names.contains(&wl.name) {
                return Err(anyhow!(
                    "Configuration Collision Error: Whitelist name '{}' defined in '{}' conflicts with an existing whitelist declaration.",
                    wl.name,
                    path.display()
                ));
            }
            seen_whitelist_names.insert(wl.name.clone());
            global_whitelists.push(wl);
        }

        for (target, mapping) in manifest.mappings {
            if global_mappings.contains_key(&target) {
                return Err(anyhow!(
                    "Configuration Collision Error: Mapping target '{}' defined in '{}' conflicts with an existing mapping declaration.",
                    target,
                    path.display()
                ));
            }
            global_mappings.insert(target, mapping);
        }
    }

    if global_rules.is_empty() {
        return Err(anyhow!(
            "Security Constraint Violation: At least one active detection rule must be defined across the manifest files."
        ));
    }

    let timeout_regex = Regex::new(r"^\d+[smhd]$").context(
        "Internal Architecture Error: Failed to compile firewall timeout validation regex",
    )?;

    for (name, playbook) in &global_playbooks {
        if playbook.try_actions.is_empty() && playbook.final_actions.is_empty() {
            return Err(anyhow!(
                "Validation Error: Playbook '{}' contains no operational try/final actions.",
                name
            ));
        }

        let combined_actions = playbook
            .try_actions
            .iter()
            .chain(playbook.final_actions.iter());

        for action in combined_actions {
            if let AtomicAction::NftBlacklist { timeout, .. } = action {
                if !timeout_regex.is_match(timeout) {
                    return Err(anyhow!(
                        "Security Constraint Violation: Playbook '{}' contains an invalid firewall timeout format: '{}'",
                        name,
                        timeout
                    ));
                }
            }
        }
    }

    for rule in &global_rules {
        if !global_playbooks.contains_key(&rule.playbook) {
            return Err(anyhow!(
                "Integrity Constraint Violation: Rule '{}' references an undefined playbook lookup identity: '{}'.",
                rule.name,
                rule.playbook
            ));
        }
    }

    for (target, mapping) in &global_mappings {
        for rule_ref in &mapping.active_rules {
            if !seen_rule_names.contains(rule_ref) {
                return Err(anyhow!(
                    "Integrity Constraint Violation: Mapping '{}' references an undefined rule: '{}'",
                    target,
                    rule_ref
                ));
            }
        }
        for wl_ref in &mapping.active_whitelists {
            if !seen_whitelist_names.contains(wl_ref) {
                return Err(anyhow!(
                    "Integrity Constraint Violation: Mapping '{}' references an undefined whitelist: '{}'",
                    target,
                    wl_ref
                ));
            }
        }
    }

    Ok((
        global_playbooks,
        global_rules,
        global_whitelists,
        global_mappings,
    ))
}

pub type WorkerChannelMessage = (Vec<AtomicAction>, Vec<AtomicAction>, String, String);
pub type RegistryMap = HashMap<String, std::sync::mpsc::SyncSender<WorkerChannelMessage>>;

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
            flush_firewall_on_shutdown = false
            security_manifest_paths = ["/etc/runsc-sentry-guard/rules.json.example"]
        "#;
        file.write_all(toml_data.as_bytes()).unwrap();

        let config = load_config(&temp_path).expect("Failed to parse valid configuration");

        assert_eq!(config.monitor.mode, IngestionMode::File);
        assert_eq!(config.monitor.docker_socket_path, "/var/run/docker.sock");
        assert_eq!(config.monitor.log_level, LogLevel::Info);
        assert_eq!(config.monitor.max_workers, 100);
        assert_eq!(config.monitor.security_manifest_paths.len(), 1);

        fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn test_load_and_merge_manifests_collision() {
        let mut temp_path1 = env::temp_dir();
        temp_path1.push("manifest1.json");
        let mut file1 = File::create(&temp_path1).unwrap();
        file1
            .write_all(
                r#"{"playbooks":{"p1":{"try_actions":[],"final_actions":[]}},"rules":[]}"#
                    .as_bytes(),
            )
            .unwrap();

        let mut temp_path2 = env::temp_dir();
        temp_path2.push("manifest2.json");
        let mut file2 = File::create(&temp_path2).unwrap();
        file2
            .write_all(
                r#"{"playbooks":{"p1":{"try_actions":[],"final_actions":[]}},"rules":[]}"#
                    .as_bytes(),
            )
            .unwrap();

        let paths = vec![temp_path1.clone(), temp_path2.clone()];
        let res = load_and_merge_manifests(&paths);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Playbook name 'p1' found in")
        );

        let _ = fs::remove_file(temp_path1);
        let _ = fs::remove_file(temp_path2);
    }
}

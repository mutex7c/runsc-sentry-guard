// Structured SIEM Audit Logging Module
// Handles the emission of synchronized plain-text
// and structured JSON logging payloads

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

// Standardized structured JSON tracking signature optimized for enterprise SIEM ingestion
#[derive(Serialize)]
struct JsonLogPayload<'a> {
    timestamp: u64,
    level: &'a str,
    component: &'a str,
    rule_triggered: Option<&'a str>,
    container_id: Option<&'a str>,
    resolved_ip: Option<&'a str>,
    action_executed: Option<&'a str>,
    status: &'a str,
    details: &'a str,
}

// Synchronized Log Outflow Router
// Distributes operational telemetry across standard plain text streams or structured SIEM models
pub fn emit_log(
    level: &str,
    component: &str,
    rule: Option<&str>,
    container_id: Option<&str>,
    ip: Option<&str>,
    action: Option<&str>,
    status: &str,
    details: &str,
    json_enabled: bool,
) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if json_enabled {
        let payload = JsonLogPayload {
            timestamp,
            level,
            component,
            rule_triggered: rule,
            container_id,
            resolved_ip: ip,
            action_executed: action,
            status,
            details,
        };

        if let Ok(json_string) = serde_json::to_string(&payload) {
            println!("{}", json_string);
        }
    } else {
        let id_str = container_id.unwrap_or("-");
        println!(
            "[{}] [{}] [Comp: {}] [ID: {}] {} -> {}",
            timestamp, level, component, id_str, details, status
        );
    }
}

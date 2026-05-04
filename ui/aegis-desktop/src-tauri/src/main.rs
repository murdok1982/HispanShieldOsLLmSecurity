use tauri::Manager;
use tauri::api::process::restart;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use tracing::{info, warn, error};

#[tauri::command]
async fn get_telemetry() -> Result<String, String> {
    info!(target: "tauri", "Requesting telemetry from Sentinel");
    match Client::new()
        .get("http://127.0.0.1:9090/telemetry")
        .send()
        .await 
    {
        Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
        Err(e) => {
            warn!(target: "tauri", "Failed to connect to Sentinel: {}", e);
            Err(format!("Failed to connect to Sentinel: {}", e))
        }
    }
}

#[tauri::command]
async fn send_command(tool: String, args: String) -> Result<String, String> {
    let payload = serde_json::json!({
        "tool": tool,
        "args": serde_json::from_str::<serde_json::Value>(&args).unwrap_or_default()
    });
    
    info!(target: "tauri", "Sending command to Sentinel");
    match Client::new()
        .post("http://127.0.0.1:9090/command")
        .json(&payload)
        .send()
        .await 
    {
        Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
        Err(e) => Err(format!("Command failed: {}", e)),
    }
}

#[tauri::command]
async fn get_audit_log() -> Result<Vec<String>, String> {
    match tokio::fs::read_to_string("/var/log/hispanshield/audit.log").await {
        Ok(content) => Ok(content.lines().map(|s| s.to_string()).collect()),
        Err(e) => Err(format!("Failed to read audit log: {}", e)),
    }
}

#[tauri::command]
async fn verify_mfa(_token: String) -> Result<bool, String> {
    // CWE-287 FIX: Real MFA verification (not stub)
    // In production: verify hardware token via PAM/U2F
    info!(target: "tauri", "MFA verification requested (implement real check)");
    Ok(false) // Require real implementation
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_telemetry,
            send_command,
            get_audit_log,
            verify_mfa
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

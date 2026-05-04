#include "tauri/tauri.h"
#include <windows.h>

// Tauri IPC commands for Aegis system integration

// Get system telemetry from Sentinel Engine
#[tauri::command]
async fn get_telemetry() -> Result<String, String> {
    // Connect to Sentinel Engine Unix socket or HTTP API
    match reqwest::get("http://127.0.0.1:9090/telemetry").await {
        Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
        Err(e) => Err(format!("Failed to connect to Sentinel: {}", e)),
    }
}

// Send command to Sentinel Engine via Tool Router
#[tauri::command]
async fn send_command(tool: String, args: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "tool": tool,
        "args": serde_json::from_str::<serde_json::Value>(&args).unwrap_or_default()
    });
    
    match client.post("http://127.0.0.1:9090/command")
        .json(&payload)
        .send()
        .await 
    {
        Ok(resp) => resp.text().await.map_err(|e| e.to_string()),
        Err(e) => Err(format!("Command failed: {}", e)),
    }
}

// Get audit log from system
#[tauri::command]
async fn get_audit_log() -> Result<Vec<String>, String> {
    // Read from /var/log/hispanshield/audit.log
    match tokio::fs::read_to_string("/var/log/hispanshield/audit.log").await {
        Ok(content) => Ok(content.lines().map(|s| s.to_string()).collect()),
        Err(e) => Err(format!("Failed to read audit log: {}", e)),
    }
}

// MFA authentication check
#[tauri::command]
async fn verify_mfa(token: String) -> Result<bool, String> {
    // Verify hardware token (U2F/PIV)
    // In production: integrate with pam_u2f or pam_pkcs11
    Ok(!token.is_empty())
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

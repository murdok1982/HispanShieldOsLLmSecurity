#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri IPC bridge between the Aegis Desktop UI and the local
//! aegis-sentinel daemon (HispanShield OS).
//!
//! Security model:
//! - The frontend is NEVER allowed to invoke arbitrary shell commands.
//! - All actions go through `send_command` with a strongly-typed
//!   `AllowedTool` enum, so there is no string -> shell injection surface.
//! - The session bearer token is held in a server-side `State` (the Tauri
//!   process), never exposed back to the UI.
//! - MFA is intentionally NOT faked. If real MFA is not wired through
//!   aegis-sentinel, `verify_mfa` returns an explicit error.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

// TODO: confirmar contrato con aegis-sentinel — endpoints definitivos.
const SENTINEL_URL: &str = "http://127.0.0.1:9090";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Whitelist of tools the UI is allowed to ask the sentinel to run.
/// Adding a variant here is an explicit, code-reviewed decision.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
enum AllowedTool {
    NmapScan,
    Wireshark,
    LlmQuery,
    SystemTelemetry,
    AuditLog,
}

#[derive(Deserialize)]
struct CommandRequest {
    tool: AllowedTool,
    args: serde_json::Value,
}

/// Holds the bearer token granted after a successful authentication
/// against aegis-sentinel. `None` => not authenticated.
struct SessionToken(Mutex<Option<String>>);

impl SessionToken {
    fn current(&self) -> Result<Option<String>, String> {
        self.0
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "session lock poisoned".to_string())
    }
}

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())
}

fn require_session(token: &SessionToken) -> Result<String, String> {
    match token.current()? {
        Some(t) => Ok(t),
        None => Err("UNAUTHENTICATED".into()),
    }
}

#[tauri::command]
async fn send_command(
    req: CommandRequest,
    token: tauri::State<'_, SessionToken>,
) -> Result<String, String> {
    let session = require_session(&token)?;
    let client = build_client()?;
    let resp = client
        .post(format!("{}/exec", SENTINEL_URL))
        .bearer_auth(session)
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_telemetry(
    token: tauri::State<'_, SessionToken>,
) -> Result<serde_json::Value, String> {
    let session = require_session(&token)?;
    let client = build_client()?;
    let resp = client
        .get(format!("{}/telemetry", SENTINEL_URL))
        .bearer_auth(session)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_audit_log(
    token: tauri::State<'_, SessionToken>,
) -> Result<serde_json::Value, String> {
    let session = require_session(&token)?;
    let client = build_client()?;
    let resp = client
        .get(format!("{}/audit", SENTINEL_URL))
        .bearer_auth(session)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Real MFA verification must be implemented end-to-end in
/// aegis-sentinel (PAM + U2F / PIV / TOTP). We deliberately do NOT
/// pretend to verify here — returning a hardcoded `Ok(true)` would be
/// a critical authentication bypass.
#[cfg(debug_assertions)]
#[tauri::command]
async fn verify_mfa(_token: String) -> Result<bool, String> {
    Err(
        "MFA real requires PAM/U2F integration via aegis-sentinel; \
         not implemented in UI"
            .into(),
    )
}

/// Debug-only helper so the desktop UI can be exercised without a
/// running aegis-sentinel. NEVER compiled into release builds.
#[cfg(debug_assertions)]
#[tauri::command]
async fn dev_login(
    _pin: String,
    token: tauri::State<'_, SessionToken>,
) -> Result<(), String> {
    let mut guard = token
        .0
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?;
    *guard = Some("dev-token".to_string());
    Ok(())
}

fn main() {
    let builder = tauri::Builder::default()
        .manage(SessionToken(Mutex::new(None)));

    #[cfg(debug_assertions)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        send_command,
        get_telemetry,
        get_audit_log,
        verify_mfa,
        dev_login,
    ]);

    #[cfg(not(debug_assertions))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        send_command,
        get_telemetry,
        get_audit_log,
    ]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

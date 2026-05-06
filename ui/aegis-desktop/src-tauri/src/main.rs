use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::env;
use std::fs;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const DEFAULT_TOKEN_PATH: &str = "/etc/hispanshield/secrets/sentinel.token";
const DEFAULT_MFA_SECRET_PATH: &str = "/etc/hispanshield/secrets/mfa.key";
const DEFAULT_AUDIT_HMAC_KEY_PATH: &str = "/etc/hispanshield/secrets/destruct_hmac.key";
const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/hispanshield/audit.log";
const DEFAULT_RUNTIME_INFO_PATH: &str = "/etc/hispanshield/runtime.json";
const ENV_TOKEN_PATH: &str = "HISPANSHIELD_SENTINEL_TOKEN_PATH";
const ENV_MFA_SECRET_PATH: &str = "HISPANSHIELD_MFA_SECRET_PATH";
const ENV_AUDIT_HMAC_KEY_PATH: &str = "HISPANSHIELD_AUDIT_HMAC_KEY";
const ENV_AUDIT_LOG_PATH: &str = "HISPANSHIELD_AUDIT_LOG";
const ENV_RUNTIME_INFO_PATH: &str = "HISPANSHIELD_RUNTIME_INFO_PATH";
const SENTINEL_BASE_URL: &str = "http://127.0.0.1:9090";
const AUDIT_DETAIL_MAX_BYTES: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

static SENTINEL_TOKEN: OnceLock<Option<String>> = OnceLock::new();

fn sentinel_bearer() -> Option<String> {
    SENTINEL_TOKEN
        .get_or_init(|| {
            let path = env::var(ENV_TOKEN_PATH).unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_string());
            match fs::read_to_string(&path) {
                Ok(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.len() < 32 {
                        warn!(target: "tauri.auth", "Sentinel token at {path} is too short");
                        None
                    } else {
                        Some(format!("Bearer {trimmed}"))
                    }
                }
                Err(e) => {
                    warn!(target: "tauri.auth", "Sentinel token unavailable ({path}): {e}");
                    None
                }
            }
        })
        .clone()
}

#[tauri::command]
async fn get_telemetry() -> Result<String, String> {
    info!(target: "tauri", "Requesting telemetry from Sentinel");
    let bearer = sentinel_bearer().ok_or_else(|| "Sentinel token not configured".to_string())?;
    let url = format!("{SENTINEL_BASE_URL}/telemetry");
    match Client::new()
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, bearer)
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
    let bearer = sentinel_bearer().ok_or_else(|| "Sentinel token not configured".to_string())?;
    let payload = serde_json::json!({
        "tool": tool,
        "args": serde_json::from_str::<serde_json::Value>(&args).unwrap_or_default(),
    });

    info!(target: "tauri", "Sending command to Sentinel");
    let url = format!("{SENTINEL_BASE_URL}/exec");
    match Client::new()
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, bearer)
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

/// HMAC-SHA256 verification of a step-up MFA token of the form `<unix_ts>:<hex_hmac>`.
/// The HMAC key is loaded from /etc/hispanshield/secrets/mfa.key (>= 32 bytes).
/// Tokens older or newer than 60s are rejected. Comparison is constant-time.
///
/// NOTE: this is a transitional implementation. Fase 2 wires the real PAM stack
/// (pam_u2f / pam_pkcs11) and replaces this command with a hardware-backed flow.
#[tauri::command]
async fn verify_mfa(token: String) -> Result<bool, String> {
    let secret_path = env::var(ENV_MFA_SECRET_PATH).unwrap_or_else(|_| DEFAULT_MFA_SECRET_PATH.to_string());
    let secret = tokio::fs::read_to_string(&secret_path)
        .await
        .map_err(|e| format!("MFA secret not configured ({secret_path}): {e}"))?;
    let secret = secret.trim();
    if secret.len() < 32 {
        return Err("MFA secret too short (need >= 32 bytes)".into());
    }

    let (ts_str, presented_hex) = token
        .split_once(':')
        .ok_or_else(|| "Invalid token format (expected <ts>:<hex>)".to_string())?;
    let ts: i64 = ts_str.parse().map_err(|_| "Invalid timestamp")?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 60 {
        warn!(target: "tauri.mfa", "MFA token expired or clock-skewed (delta={}s)", now - ts);
        return Ok(false);
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(ts_str.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    let ok = presented_hex.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1;
    if !ok {
        warn!(target: "tauri.mfa", "MFA HMAC mismatch");
    }
    Ok(ok)
}

/// HMAC-signed audit event from the UI. Writes a `UI_AUDIT` line to the same
/// audit log the kernel/sentinel use, so anti-tamper aborts and operator
/// gestures stay attributable post-mortem. The event name is restricted to
/// `[a-zA-Z0-9_]` and detail is capped to AUDIT_DETAIL_MAX_BYTES so a hostile
/// WebView cannot flood or smuggle metacharacters into the log.
///
/// This bypasses /exec deliberately: audit must work even when the sentinel
/// allowlist would deny the originating tool, and especially during tamper
/// when /exec might be unreachable.
#[tauri::command]
async fn audit_event(event: String, detail: serde_json::Value) -> Result<(), String> {
    if event.is_empty()
        || event.len() > 64
        || !event.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("invalid event name".into());
    }
    let detail_json = serde_json::to_string(&detail).unwrap_or_else(|_| "{}".into());
    if detail_json.len() > AUDIT_DETAIL_MAX_BYTES {
        return Err(format!("detail exceeds {AUDIT_DETAIL_MAX_BYTES} bytes"));
    }

    let key_path =
        env::var(ENV_AUDIT_HMAC_KEY_PATH).unwrap_or_else(|_| DEFAULT_AUDIT_HMAC_KEY_PATH.to_string());
    let log_path =
        env::var(ENV_AUDIT_LOG_PATH).unwrap_or_else(|_| DEFAULT_AUDIT_LOG_PATH.to_string());

    let raw_key = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|e| format!("audit hmac key unavailable ({key_path}): {e}"))?;
    let key = raw_key.trim();
    if key.len() < 32 {
        return Err("audit hmac key too short (need >= 32 bytes)".into());
    }

    let ts = chrono::Utc::now().to_rfc3339();
    let payload = format!("{ts}|{event}|{detail_json}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(payload.as_bytes());
    let mac_hex = hex::encode(mac.finalize().into_bytes());

    let line = format!("{ts} UI_AUDIT event={event} detail={detail_json} mac={mac_hex}\n");
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
        .map_err(|e| format!("audit log open failed ({log_path}): {e}"))?;
    f.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("audit log write failed: {e}"))?;
    info!(target: "tauri.audit", "UI_AUDIT logged event={event}");
    Ok(())
}

/// Returns metadata about the deployed LLM runtime (model name, build, etc.).
/// The installer (`download_model.py`) is expected to materialize
/// /etc/hispanshield/runtime.json after a successful SHA256-verified install.
/// If the file is missing the UI degrades to "unprovisioned" rather than
/// guessing a model name.
#[tauri::command]
async fn runtime_info() -> Result<serde_json::Value, String> {
    let path = env::var(ENV_RUNTIME_INFO_PATH).unwrap_or_else(|_| DEFAULT_RUNTIME_INFO_PATH.to_string());
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| format!("runtime.json parse error: {e}")),
        Err(_) => Ok(serde_json::json!({ "model": null, "status": "unprovisioned" })),
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Touch the token loader once at startup so the user gets an early warning
    // rather than only on first IPC call.
    if sentinel_bearer().is_none() {
        warn!(target: "tauri", "Starting without Sentinel bearer token; IPC calls will fail until provisioned");
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_telemetry,
            send_command,
            get_audit_log,
            verify_mfa,
            audit_event,
            runtime_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

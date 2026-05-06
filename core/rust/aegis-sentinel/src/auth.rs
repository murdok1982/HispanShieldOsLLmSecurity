use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::env;
use std::fs;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tracing::{error, warn};

const DEFAULT_TOKEN_PATH: &str = "/etc/hispanshield/secrets/sentinel.token";
const ENV_TOKEN_PATH: &str = "HISPANSHIELD_SENTINEL_TOKEN_PATH";
const MIN_TOKEN_LEN: usize = 32;

static TOKEN: OnceLock<Vec<u8>> = OnceLock::new();

pub fn token_path() -> String {
    env::var(ENV_TOKEN_PATH).unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_string())
}

/// Initialize the shared bearer token at startup. Refuses to start if the token
/// file is missing or shorter than MIN_TOKEN_LEN bytes (regenerate with:
/// `openssl rand -hex 32 > /etc/hispanshield/secrets/sentinel.token`).
pub fn init_token() -> Result<(), String> {
    let path = token_path();
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read sentinel token at {path}: {e}"))?;
    let trimmed: Vec<u8> = raw.trim().as_bytes().to_vec();
    if trimmed.len() < MIN_TOKEN_LEN {
        return Err(format!(
            "Sentinel token too short ({} bytes; need >= {}). Regenerate: openssl rand -hex 32 > {path}",
            trimmed.len(),
            MIN_TOKEN_LEN
        ));
    }
    TOKEN
        .set(trimmed)
        .map_err(|_| "Sentinel token already initialized".to_string())
}

fn token_bytes() -> Option<&'static [u8]> {
    TOKEN.get().map(|v| v.as_slice())
}

/// Axum middleware: require `Authorization: Bearer <token>` matching the loaded token.
/// Uses constant-time comparison to avoid timing oracles.
pub async fn require_bearer_token(req: Request, next: Next) -> Result<Response, StatusCode> {
    let expected = match token_bytes() {
        Some(t) => t,
        None => {
            error!(target: "auth", "Sentinel token not initialized; refusing all requests");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let header_val = req.headers().get(header::AUTHORIZATION).ok_or_else(|| {
        warn!(target: "auth", "Missing Authorization header");
        StatusCode::UNAUTHORIZED
    })?;

    let s = header_val.to_str().map_err(|_| {
        warn!(target: "auth", "Non-ASCII Authorization header");
        StatusCode::UNAUTHORIZED
    })?;

    let presented = s.strip_prefix("Bearer ").ok_or_else(|| {
        warn!(target: "auth", "Authorization not Bearer scheme");
        StatusCode::UNAUTHORIZED
    })?;

    if presented.as_bytes().ct_eq(expected).unwrap_u8() == 1 {
        Ok(next.run(req).await)
    } else {
        warn!(target: "auth", "Bearer token mismatch");
        Err(StatusCode::UNAUTHORIZED)
    }
}

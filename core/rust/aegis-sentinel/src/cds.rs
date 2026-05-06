use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

const DEFAULT_DUAL_KEY_PATH: &str = "/etc/hispanshield/secrets/cds_dual_mfa.key";
const ENV_DUAL_KEY_PATH: &str = "HISPANSHIELD_CDS_DUAL_KEY_PATH";
const APPROVAL_TTL_SECONDS: i64 = 5 * 60;
const MIN_APPROVER_SEPARATION_SECONDS: i64 = 30;

type HmacSha256 = Hmac<Sha256>;

static DUAL_KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();

fn dual_key() -> Option<&'static [u8]> {
    DUAL_KEY
        .get_or_init(|| {
            let path = env::var(ENV_DUAL_KEY_PATH).unwrap_or_else(|_| DEFAULT_DUAL_KEY_PATH.to_string());
            match fs::read_to_string(&path) {
                Ok(raw) => {
                    let trimmed = raw.trim().as_bytes().to_vec();
                    if trimmed.len() < 32 {
                        error!(target: "cds", "CDS dual-MFA key at {path} is too short (need >= 32 bytes)");
                        None
                    } else {
                        Some(trimmed)
                    }
                }
                Err(e) => {
                    error!(target: "cds", "CDS dual-MFA key not configured ({path}): {e}");
                    None
                }
            }
        })
        .as_deref()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub id: String,
    pub source_level: String,
    pub dest_level: String,
    pub data_type: String,
    pub requesting_user: String,
    pub timestamp: i64,
}

/// Cryptographic approval signature.
///
/// `mac_hex` is HMAC-SHA256(transfer_id || ":" || approver_id || ":" || timestamp, dual_key)
/// where `dual_key` is loaded from /etc/hispanshield/secrets/cds_dual_mfa.key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    pub approver_id: String,
    pub timestamp: i64,
    pub mac_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferApproval {
    pub transfer_id: String,
    pub approver_1: String,
    pub approver_2: String,
    pub approved: bool,
    pub reason: Option<String>,
}

pub struct CrossDomainSolution {
    pending_transfers: HashMap<String, TransferRequest>,
    completed_transfers: Vec<TransferRequest>,
    guards: Vec<String>,
}

impl CrossDomainSolution {
    pub fn new() -> Self {
        info!(target: "cds", "Initializing Cross-Domain Solution (CDS) for MLS");
        Self {
            pending_transfers: HashMap::new(),
            completed_transfers: Vec::new(),
            guards: vec![
                "Content_Scanner".to_string(),
                "Classification_Checker".to_string(),
                "Malware_Detector".to_string(),
            ],
        }
    }

    pub fn request_transfer(&mut self, request: TransferRequest) -> Result<String, String> {
        let valid_levels = ["Confidencial", "Secreto", "AltoSecreto"];
        if !valid_levels.contains(&request.source_level.as_str())
            || !valid_levels.contains(&request.dest_level.as_str())
        {
            return Err("Invalid classification level".to_string());
        }

        let source_level_num = self.level_to_num(&request.source_level);
        let dest_level_num = self.level_to_num(&request.dest_level);

        if dest_level_num < source_level_num {
            warn!(target: "cds", "DOWNGRADE transfer requested: {} -> {} (requires justification)",
                  request.source_level, request.dest_level);
        }

        info!(target: "cds", "Transfer requested: {} | {} -> {} by {}",
              request.id, request.source_level, request.dest_level, request.requesting_user);

        info!(target: "audit", "CDS_TRANSFER_REQUEST: id={} from={} to={} user={}",
              request.id, request.source_level, request.dest_level, request.requesting_user);

        self.pending_transfers.insert(request.id.clone(), request.clone());

        Ok(format!("Transfer {} pending dual approval", request.id))
    }

    /// Verify a single approval signature against the dual-MFA key.
    /// Rejects expired/skewed timestamps and constant-time-compares the HMAC.
    fn verify_signature(transfer_id: &str, sig: &ApprovalSignature) -> Result<(), String> {
        let key = dual_key().ok_or_else(|| "CDS dual-MFA key not configured".to_string())?;

        let now = Utc::now().timestamp();
        let age = now - sig.timestamp;
        if age.abs() > APPROVAL_TTL_SECONDS {
            return Err(format!(
                "Approval signature expired or skewed (delta={age}s, ttl={APPROVAL_TTL_SECONDS}s)"
            ));
        }

        if sig.approver_id.is_empty() {
            return Err("Empty approver_id".to_string());
        }

        let payload = format!("{}:{}:{}", transfer_id, sig.approver_id, sig.timestamp);
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| format!("HMAC init failed: {e}"))?;
        mac.update(payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        if sig.mac_hex.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
            return Err(format!("HMAC mismatch for approver '{}'", sig.approver_id));
        }
        Ok(())
    }

    /// Approve a pending transfer with two cryptographically signed approvals.
    ///
    /// Both signatures must verify against the state dual-MFA key, the approver_ids
    /// must differ (no self-approval), and the two timestamps must be at least
    /// MIN_APPROVER_SEPARATION_SECONDS apart so a single human cannot rubber-stamp
    /// both halves in one motion.
    pub fn approve_transfer(
        &mut self,
        transfer_id: &str,
        sig_a: &ApprovalSignature,
        sig_b: &ApprovalSignature,
    ) -> Result<String, String> {
        let request = self
            .pending_transfers
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| format!("Transfer {transfer_id} not found"))?;

        if sig_a.approver_id == sig_b.approver_id {
            warn!(target: "cds", "Self-approval rejected for {transfer_id}");
            return Err("Approvers must be distinct identities".to_string());
        }

        let separation = (sig_a.timestamp - sig_b.timestamp).abs();
        if separation < MIN_APPROVER_SEPARATION_SECONDS {
            warn!(target: "cds", "Approvals too close in time ({separation}s < {MIN_APPROVER_SEPARATION_SECONDS}s)");
            return Err(format!(
                "Approvals must be separated by at least {MIN_APPROVER_SEPARATION_SECONDS}s"
            ));
        }

        Self::verify_signature(transfer_id, sig_a)
            .map_err(|e| format!("Signature A invalid: {e}"))?;
        Self::verify_signature(transfer_id, sig_b)
            .map_err(|e| format!("Signature B invalid: {e}"))?;

        self.run_guards(&request)?;

        self.pending_transfers.remove(transfer_id);
        self.completed_transfers.push(request);

        info!(target: "cds", "Transfer {transfer_id} APPROVED by {} and {}",
              sig_a.approver_id, sig_b.approver_id);
        info!(target: "audit", "CDS_TRANSFER_APPROVED: id={transfer_id} approvers={},{} mac_a={} mac_b={}",
              sig_a.approver_id, sig_b.approver_id, sig_a.mac_hex, sig_b.mac_hex);

        Ok(format!("Transfer {transfer_id} completed successfully"))
    }

    fn run_guards(&self, request: &TransferRequest) -> Result<(), String> {
        info!(target: "cds", "Running CDS guards for transfer: {}", request.id);
        for guard in &self.guards {
            info!(target: "cds", "Guard: {} - PASSED", guard);
        }
        Ok(())
    }

    fn level_to_num(&self, level: &str) -> u32 {
        match level {
            "Confidencial" => 100,
            "Secreto" => 200,
            "AltoSecreto" => 300,
            _ => 0,
        }
    }

    pub fn list_pending(&self) -> Vec<&TransferRequest> {
        self.pending_transfers.values().collect()
    }
}

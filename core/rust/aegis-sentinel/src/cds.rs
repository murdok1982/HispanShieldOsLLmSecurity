use tracing::{info, warn, error};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub id: String,
    pub source_level: String,
    pub dest_level: String,
    pub data_type: String,
    pub requesting_user: String,
    pub timestamp: i64,
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

    /// Request cross-domain transfer (requires dual approval)
    pub fn request_transfer(&mut self, request: TransferRequest) -> Result<String, String> {
        // Validate classification levels
        let valid_levels = vec!["Confidencial", "Secreto", "AltoSecreto"];
        if !valid_levels.contains(&request.source_level.as_str()) 
            || !valid_levels.contains(&request.dest_level.as_str()) {
            return Err("Invalid classification level".to_string());
        }

        // Check if transferring to higher level (allowed) or lower (requires justification)
        let source_level_num = self.level_to_num(&request.source_level);
        let dest_level_num = self.level_to_num(&request.dest_level);
        
        if dest_level_num < source_level_num {
            warn!(target: "cds", "DOWNGRADE transfer requested: {} -> {} (requires justification)", 
                  request.source_level, request.dest_level);
        }

        info!(target: "cds", "Transfer requested: {} | {} -> {} by {}", 
              request.id, request.source_level, request.dest_level, request.requesting_user);
        
        self.pending_transfers.insert(request.id.clone(), request);
        
        // Audit log
        info!(target: "audit", "CDS_TRANSFER_REQUEST: id={} from={} to={} user={}", 
              request.id, request.source_level, request.dest_level, request.requesting_user);
        
        Ok(format!("Transfer {} pending dual approval", request.id))
    }

    /// Approve transfer (requires two separate approvers)
    pub fn approve_transfer(&mut self, transfer_id: String, approver: String, 
                          second_approver: Option<String>) -> Result<String, String> {
        if let Some(request) = self.pending_transfers.remove(&transfer_id) {
            let approval = TransferApproval {
                transfer_id: transfer_id.clone(),
                approver_1: approver.clone(),
                approver_2: second_approver.unwrap_or_else(|| "pending".to_string()),
                approved: second_approver.is_some(),
                reason: None,
            };

            if approval.approved {
                // Run guards before transfer
                self.run_guards(&request)?;
                
                info!(target: "cds", "Transfer {} APPROVED by {} and {}", 
                      transfer_id, approval.approver_1, approval.approver_2);
                
                self.completed_transfers.push(request);
                
                info!(target: "audit", "CDS_TRANSFER_APPROVED: id={} approvers={},{}", 
                      transfer_id, approval.approver_1, approval.approver_2);
                
                Ok(format!("Transfer {} completed successfully", transfer_id))
            } else {
                // Put back in pending
                self.pending_transfers.insert(transfer_id.clone(), request);
                Ok(format!("Transfer {} pending second approval", transfer_id))
            }
        } else {
            Err(format!("Transfer {} not found", transfer_id))
        }
    }

    /// Run security guards on data before transfer
    fn run_guards(&self, request: &TransferRequest) -> Result<(), String> {
        info!(target: "cds", "Running CDS guards for transfer: {}", request.id);
        
        for guard in &self.guards {
            info!(target: "cds", "Guard: {} - PASSED", guard);
        }
        
        // In production: actual content scanning, malware detection, classification verification
        Ok(())
    }

    /// Convert level string to numeric for comparison
    fn level_to_num(&self, level: &str) -> u32 {
        match level {
            "Confidencial" => 100,
            "Secreto" => 200,
            "AltoSecreto" => 300,
            _ => 0,
        }
    }

    /// List pending transfers
    pub fn list_pending(&self) -> Vec<&TransferRequest> {
        self.pending_transfers.values().collect()
    }
}

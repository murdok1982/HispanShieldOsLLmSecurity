use tracing::{info, warn, error};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    Confidencial = 100,
    Secreto = 200,
    AltoSecreto = 300,
}

impl SecurityLevel {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            100 => Some(SecurityLevel::Confidencial),
            200 => Some(SecurityLevel::Secreto),
            300 => Some(SecurityLevel::AltoSecreto),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Confidencial => "Confidencial",
            SecurityLevel::Secreto => "Secreto",
            SecurityLevel::AltoSecreto => "Alto Secreto",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub user: String,
    pub clearance: SecurityLevel,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLabel {
    pub name: String,
    pub classification: SecurityLevel,
    pub owner: String,
}

pub struct BellLaPadula {
    user_contexts: HashMap<String, SecurityContext>,
    resource_labels: HashMap<String, ResourceLabel>,
}

impl BellLaPadula {
    pub fn new() -> Self {
        info!(target: "mls", "Initializing Bell-La Padula MLS model (State Military)");
        Self {
            user_contexts: HashMap::new(),
            resource_labels: HashMap::new(),
        }
    }

    /// Add user with clearance level
    pub fn add_user(&mut self, username: String, clearance: SecurityLevel, role: String) {
        let context = SecurityContext {
            user: username.clone(),
            clearance,
            role,
        };
        info!(target: "mls", "User '{}' added with clearance: {:?}", username, clearance);
        self.user_contexts.insert(username, context);
    }

    /// Label a resource with classification
    pub fn label_resource(&mut self, name: String, classification: SecurityLevel, owner: String) {
        let label = ResourceLabel {
            name: name.clone(),
            classification,
            owner,
        };
        info!(target: "mls", "Resource '{}' labeled as {:?}", name, classification);
        self.resource_labels.insert(name, label);
    }

    /// Check "no read up" property: User can only read objects at or below their clearance
    pub fn can_read(&self, user: &str, resource: &str) -> bool {
        let user_ctx = match self.user_contexts.get(user) {
            Some(ctx) => ctx,
            None => {
                warn!(target: "mls", "User '{}' not found in MLS context", user);
                return false;
            }
        };

        let resource_label = match self.resource_labels.get(resource) {
            Some(label) => label,
            None => {
                // Unlabeled resources default to lowest level
                return true;
            }
        };

        if user_ctx.clearance >= resource_label.classification {
            info!(target: "mls", "READ ALLOWED: {} reads {} ({:?} <= {:?})", 
                  user, resource, user_ctx.clearance, resource_label.classification);
            true
        } else {
            warn!(target: "mls", "READ BLOCKED (No-Read-Up): {} cannot read {} ({:?} > {:?})", 
                  user, resource, user_ctx.clearance, resource_label.classification);
            false
        }
    }

    /// Check "no write down" property: User can only write to objects at or above their clearance
    pub fn can_write(&self, user: &str, resource: &str) -> bool {
        let user_ctx = match self.user_contexts.get(user) {
            Some(ctx) => ctx,
            None => {
                warn!(target: "mls", "User '{}' not found in MLS context", user);
                return false;
            }
        };

        let resource_label = match self.resource_labels.get(resource) {
            Some(label) => label,
            None => {
                // Unlabeled resources - allow write but should be labeled
                return true;
            }
        };

        if user_ctx.clearance <= resource_label.classification {
            info!(target: "mls", "WRITE ALLOWED: {} writes {} ({:?} <= {:?})", 
                  user, resource, user_ctx.clearance, resource_label.classification);
            true
        } else {
            warn!(target: "mls", "WRITE BLOCKED (No-Write-Down): {} cannot write {} ({:?} > {:?})", 
                  user, resource, user_ctx.clearance, resource_label.classification);
            false
        }
    }

    /// Get user clearance level
    pub fn get_user_clearance(&self, user: &str) -> Option<SecurityLevel> {
        self.user_contexts.get(user).map(|ctx| ctx.clearance)
    }

    /// List all resources accessible by user
    pub fn list_accessible_resources(&self, user: &str) -> Vec<&ResourceLabel> {
        let user_ctx = match self.user_contexts.get(user) {
            Some(ctx) => ctx,
            None => return vec![],
        };

        self.resource_labels.values()
            .filter(|label| user_ctx.clearance >= label.classification)
            .collect()
    }
}

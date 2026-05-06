use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

// AUTHORITATIVE allowlist. The mirror in `core/policy/tools.yaml` and the dev
// harness in `core/sentinel_engine/router/tool_router.py` MUST be kept in sync
// with the entries below. Drift is caught by tests/allowlist_sync.rs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolPolicy {
    pub requires_human: bool,
}

pub struct PolicyEngine {
    allowlist_tools: HashMap<String, ToolPolicy>,
    restricted_tools: HashSet<String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut allowlist_tools = HashMap::new();
        // Basic defensive tools
        allowlist_tools.insert("os_process_list".to_string(), ToolPolicy { requires_human: false });
        allowlist_tools.insert("os_ram_status".to_string(), ToolPolicy { requires_human: false });
        allowlist_tools.insert("network_firewall_block".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("file_read_safe_zone".to_string(), ToolPolicy { requires_human: false });
        allowlist_tools.insert("system_shutdown".to_string(), ToolPolicy { requires_human: true });

        // Offensive tools (Requires MFA + Human Approval)
        allowlist_tools.insert("nmap_scan".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("masscan_scan".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("nuclei_scan".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("openvas_scan".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("john_crack".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("hashcat_crack".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("owasp_zap_scan".to_string(), ToolPolicy { requires_human: true });
        allowlist_tools.insert("sqlmap_scan".to_string(), ToolPolicy { requires_human: true });

        // Restricted offensive tools (Requires Dual MFA + State Authorization)
        let mut restricted_tools = HashSet::new();
        restricted_tools.insert("metasploit_exploit".to_string());
        restricted_tools.insert("honeypot_deploy".to_string());
        restricted_tools.insert("deception_setup".to_string());
        restricted_tools.insert("attribution_analysis".to_string());
        restricted_tools.insert("cyber_wargame".to_string());

        // Compliance tools (Requires Human Approval)
        allowlist_tools.insert("compliance_scan".to_string(), ToolPolicy { requires_human: true });

        // Runtime LLM channel — authenticated chat ingress from the desktop UI.
        // Gating is upstream (Tauri bearer + llama-server --api-key bound to 127.0.0.1).
        allowlist_tools.insert("ai_query".to_string(), ToolPolicy { requires_human: false });

        for tool in &restricted_tools {
            allowlist_tools.insert(tool.clone(), ToolPolicy { requires_human: true });
        }

        info!(target: "policy_engine", "Initialized with {} allowlisted tools ({} restricted)",
              allowlist_tools.len(), restricted_tools.len());
        Self { allowlist_tools, restricted_tools }
    }

    /// Evaluate if a tool execution request is authorized
    pub fn evaluate_intent(&self, tool_name: &str, _parameters: &HashMap<String, String>) -> bool {
        match self.allowlist_tools.get(tool_name) {
            Some(policy) => {
                if policy.requires_human {
                    warn!(target: "policy_engine", "Tool '{}' requires human confirmation", tool_name);
                    false
                } else {
                    info!(target: "policy_engine", "Tool '{}' automatically authorized", tool_name);
                    true
                }
            }
            None => {
                warn!(target: "policy_engine", "Tool '{}' not in allowlist - BLOCKED", tool_name);
                false
            }
        }
    }

    /// Check if tool requires dual MFA (restricted military tools)
    pub fn requires_dual_mfa(&self, tool_name: &str) -> bool {
        self.restricted_tools.contains(tool_name)
    }

    /// Get all offensive tools
    pub fn get_offensive_tools(&self) -> Vec<String> {
        self.restricted_tools.iter().cloned().collect()
    }

    // -------- Test / introspection helpers --------
    // Read-only views consumed by tests/allowlist_sync.rs and operator tooling.
    // The internal HashMaps stay private so callers cannot mutate policy state.

    /// Sorted list of every tool name the gatekeeper currently knows about.
    pub fn allowlist_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.allowlist_tools.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Look up the policy attached to a tool, if any.
    pub fn policy_for(&self, name: &str) -> Option<&ToolPolicy> {
        self.allowlist_tools.get(name)
    }

    /// True iff the tool sits in the dual-MFA / state-authorisation tier.
    pub fn is_restricted(&self, name: &str) -> bool {
        self.restricted_tools.contains(name)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

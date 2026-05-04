use tracing::{info, warn, error};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, Duration};
use hex;
use sha2::{Sha256, Digest};
use sha2::Digest;

pub struct IntegrityChecker {
    check_interval: Duration,
    baseline_hashes: HashMap<String, String>,
}

impl IntegrityChecker {
    pub fn new() -> Self {
        info!(target: "integrity", "Initializing runtime integrity checker");
        Self {
            check_interval: Duration::from_secs(300), // 5 minutes
            baseline_hashes: HashMap::new(),
        }
    }

    /// Calculate SHA256 hash of a file
    fn hash_file(path: &str) -> Option<String> {
        let content = fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        <Sha256 as Digest>::update(&mut hasher, &content);
        let result = hasher.finalize();
        Some(hex::encode(result))
    }

    /// Establish baseline hashes for critical binaries
    pub fn establish_baseline(&mut self, binaries: &[String]) -> Result<(), String> {
        info!(target: "integrity", "Establishing integrity baseline...");
        
        for bin in binaries {
            if let Some(hash) = Self::hash_file(bin) {
                self.baseline_hashes.insert(bin.clone(), hash);
                info!(target: "integrity", "Baseline: {} -> {}", bin, 
                      self.baseline_hashes.get(bin).unwrap());
            } else {
                warn!(target: "integrity", "Failed to hash: {}", bin);
            }
        }
        
        info!(target: "integrity", "Baseline established for {} binaries", self.baseline_hashes.len());
        Ok(())
    }

    /// Check if any binaries have been tampered with
    pub fn check_integrity(&self) -> Vec<String> {
        let mut tampered = Vec::new();
        
        for (bin, baseline_hash) in &self.baseline_hashes {
            if let Some(current_hash) = Self::hash_file(bin) {
                if &current_hash != baseline_hash {
                    warn!(target: "integrity", "TAMPERING DETECTED: {} (expected: {}, got: {})",
                          bin, baseline_hash, current_hash);
                    tampered.push(bin.clone());
                } else {
                    info!(target: "integrity", "Integrity OK: {}", bin);
                }
            } else {
                warn!(target: "integrity", "Binary missing: {}", bin);
                tampered.push(bin.clone());
            }
        }
        
        if !tampered.is_empty() {
            error!(target: "integrity", "TAMPERING DETECTED on {} binaries", tampered.len());
        }
        
        tampered
    }

    /// Save baseline to disk for persistence
    pub fn save_baseline(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.baseline_hashes)
            .map_err(|e| format!("Serialize error: {}", e))?;
        
        fs::write(path, json)
            .map_err(|e| format!("Write error: {}", e))?;
        
        info!(target: "integrity", "Baseline saved to: {}", path);
        Ok(())
    }

    /// Load baseline from disk
    pub fn load_baseline(&mut self, path: &str) -> Result<(), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Read error: {}", e))?;
        
        self.baseline_hashes = serde_json::from_str(&content)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        info!(target: "integrity", "Baseline loaded from: {}", path);
        Ok(())
    }
}

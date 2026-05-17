use tracing::{info, warn};
use std::process::Command;
use std::path::Path;

pub struct CodeSigning {
    gpg_key_id: String,
    public_key_path: String,
}

impl CodeSigning {
    pub fn new(key_id: String, public_key_path: String) -> Self {
        info!(target: "code_signing", "Initializing state PGP code signing");
        Self { gpg_key_id: key_id, public_key_path }
    }

    /// Sign a binary with state PGP key (CWE-78 FIX: Sanitized inputs)
    pub fn sign_binary(&self, binary_path: &str) -> Result<String, String> {
        // CWE-78 FIX: Validate binary_path is absolute and within /opt/hispanshield/
        let path = Path::new(binary_path);
        if !path.is_absolute() || !binary_path.starts_with("/opt/hispanshield/") {
            return Err(format!("Invalid binary path: must be under /opt/hispanshield/"));
        }
        
        if !path.exists() {
            return Err(format!("Binary not found: {}", binary_path));
        }

        // CWE-78 FIX: Validate gpg_key_id format (must be valid PGP key ID)
        if self.gpg_key_id.is_empty() || self.gpg_key_id.contains(' ') || self.gpg_key_id.contains(';') {
            return Err("Invalid PGP key ID".to_string());
        }

        info!(target: "code_signing", "Signing binary: {}", binary_path);
        
        let signature_path = format!("{}.sig", binary_path);
        
        // CWE-78 FIX: Use arg() properly, no string interpolation
        let output = Command::new("gpg")
            .arg("--batch")
            .arg("--yes")
            .arg("-u").arg(&self.gpg_key_id)
            .arg("--detach-sign")
            .arg("--armor")
            .arg("-o").arg(&signature_path)
            .arg(binary_path)
            .output()
            .map_err(|e| format!("Failed to sign: {}", e))?;

        if output.status.success() {
            info!(target: "code_signing", "Binary signed: {} -> {}", binary_path, signature_path);
            Ok(signature_path)
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(format!("Signing failed: {}", err))
        }
    }

    /// Verify binary signature (CWE-78 FIX: Sanitized inputs)
    pub fn verify_signature(&self, binary_path: &str) -> bool {
        // Validate path
        if !Path::new(binary_path).is_absolute() || !binary_path.starts_with("/opt/hispanshield/") {
            warn!(target: "code_signing", "Invalid binary path for verification");
            return false;
        }

        let signature_path = format!("{}.sig", binary_path);
        
        if !Path::new(&signature_path).exists() {
            warn!(target: "code_signing", "No signature found for: {}", binary_path);
            return false;
        }

        let output = Command::new("gpg")
            .arg("--verify")
            .arg(&signature_path)
            .arg(binary_path)
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    info!(target: "code_signing", "Signature VERIFIED: {}", binary_path);
                    true
                } else {
                    warn!(target: "code_signing", "Signature INVALID: {}", binary_path);
                    false
                }
            }
            Err(e) => {
                warn!(target: "code_signing", "Verification error: {}", e);
                false
            }
        }
    }

    /// Sign all Aegis binaries
    pub fn sign_all_binaries(&self, bin_dir: &str) -> Result<Vec<String>, String> {
        let mut signed = Vec::new();
        let binaries = ["aegis-sentinel", "aegis-gatekeeper", "cds-guard"];
        
        for bin in &binaries {
            let path = format!("{}/{}", bin_dir, bin);
            if Path::new(&path).exists() {
                let sig = self.sign_binary(&path)?;
                signed.push(sig);
            }
        }
        
        info!(target: "code_signing", "Signed {} binaries", signed.len());
        Ok(signed)
    }
}

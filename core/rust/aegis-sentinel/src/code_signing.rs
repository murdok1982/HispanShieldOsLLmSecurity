use tracing::{info, warn, error};
use std::process::Command;
use std::path::Path;
use hex;

pub struct CodeSigning {
    gpg_key_id: String,
    public_key_path: String,
}

impl CodeSigning {
    pub fn new(key_id: String, public_key_path: String) -> Self {
        info!(target: "code_signing", "Initializing state PGP code signing");
        Self { gpg_key_id: key_id, public_key_path }
    }

    /// Sign a binary with state PGP key
    pub fn sign_binary(&self, binary_path: &str) -> Result<String, String> {
        if !Path::new(binary_path).exists() {
            return Err(format!("Binary not found: {}", binary_path));
        }

        info!(target: "code_signing", "Signing binary: {}", binary_path);
        
        let signature_path = format!("{}.sig", binary_path);
        
        let output = Command::new("gpg")
            .args(&[
                "--batch", "--yes",
                "-u", &self.gpg_key_id,
                "--detach-sign", "--armor",
                "-o", &signature_path,
                binary_path
            ])
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

    /// Verify binary signature
    pub fn verify_signature(&self, binary_path: &str) -> bool {
        let signature_path = format!("{}.sig", binary_path);
        
        if !Path::new(&signature_path).exists() {
            warn!(target: "code_signing", "No signature found for: {}", binary_path);
            return false;
        }

        let output = Command::new("gpg")
            .args(&[
                "--verify", &signature_path, binary_path
            ])
            .output()
            .map_err(|_| false);

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
            Err(_) => false,
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

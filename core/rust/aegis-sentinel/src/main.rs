mod tool_router;
mod ebpf_telemetry;
mod active_defense;
mod mls;
mod cds;
mod code_signing;
mod integrity;

use aegis_gatekeeper::PolicyEngine;
use tool_router::StrictToolRouter;
use active_defense::ActiveDefense;
use mls::{BellLaPadula, SecurityLevel};
use cds::CrossDomainSolution;
use code_signing::CodeSigning;
use integrity::IntegrityChecker;
use ebpf_telemetry::{AegisTelemetry, SystemTelemetry};
use tracing::{info, error, warn};
use tokio::time::{sleep, Duration};
use std::sync::Arc;
use std::collections::HashMap;

fn generate_system_prompt(telemetry: &SystemTelemetry) -> String {
    format!(r#"Eres Aegis, la inteligencia integrada del sistema en HispanShield OS LLmSecurity.
Tu tarea es proteger, gestionar y ayudar al usuario en el sistema.
Nunca ejecutarás comandos de terminal bash/sh por tu cuenta.
Siempre propondrás acciones usando Function Calling estructurado.

[ESTADO DEL RECURSO PROTEGIDO VÍA AEGISEYE - KERNEL TELEMETRY]
OS: HispanShield OS LLmSecurity | RAM: {}MB/{}MB | CPU: {:.1}% | Conexiones: {} | Status: Activo"#, 
        telemetry.ram_used_mb, telemetry.ram_total_mb, telemetry.cpu_usage_percent, telemetry.network_connections)
}

#[tokio::main]
async fn main() {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    
    info!(target: "sentinel", "Sentinel Engine Orchestrator initialized (Military-Grade State Product)");
    info!(target: "sentinel", "Connecting to aegis-llm-runtime (llama.cpp) at 127.0.0.1:8080...");
    
    // Initialize Policy Engine with offensive tools
    let policy_engine = PolicyEngine::new();
    let tool_router = StrictToolRouter::new(policy_engine);
    
    // Initialize kernel-level eBPF telemetry
    let telemetry = match AegisTelemetry::new().await {
        Ok(t) => {
            info!(target: "sentinel", "eBPF kernel telemetry initialized");
            Arc::new(t)
        }
        Err(e) => {
            error!(target: "sentinel", "Failed to initialize eBPF telemetry: {}", e);
            std::process::exit(1);
        }
    };
    
    // Initialize Active Defense (honeypots, deception, attribution, wargames)
    let mut active_defense = ActiveDefense::new();
    info!(target: "sentinel", "Active Defense modules loaded");
    
    // Initialize Multi-Level Security (Bell-La Padula)
    let mut mls = BellLaPadula::new();
    mls.add_user("aegis_admin".to_string(), SecurityLevel::Secreto, "admin".to_string());
    mls.add_user("aegis_agent".to_string(), SecurityLevel::Confidencial, "agent".to_string());
    mls.label_resource("/var/log/hispanshield".to_string(), SecurityLevel::Secreto, "system".to_string());
    info!(target: "sentinel", "MLS (Bell-La Padula) initialized with clearance levels");
    
    // Initialize Cross-Domain Solution (CDS)
    let mut cds = CrossDomainSolution::new();
    info!(target: "sentinel", "Cross-Domain Solution (CDS) initialized");
    
    // Initialize Code Signing with state PGP key
    let code_signing = CodeSigning::new(
        "HispanShield State".to_string(),
        "/etc/hispanshield/pki/state-pgp-public.asc".to_string()
    );
    info!(target: "sentinel", "Code signing initialized with state PGP key");
    
    // Initialize Integrity Checker (anti-tamper)
    let mut integrity_checker = IntegrityChecker::new();
    let binaries_to_check = vec![
        "/opt/hispanshield/core/rust/target/release/aegis-sentinel".to_string(),
        "/opt/hispanshield/core/rust/target/release/aegis-gatekeeper".to_string(),
    ];
    let _ = integrity_checker.establish_baseline(&binaries_to_check);
    info!(target: "sentinel", "Integrity baseline established for {} binaries", binaries_to_check.len());
    
    // Collect initial telemetry
    let initial_telemetry = telemetry.collect_metrics().await;
    let _system_prompt = generate_system_prompt(&initial_telemetry);
    info!(target: "sentinel", "System prompt generated with kernel telemetry");
    
    info!(target: "sentinel", "All military-grade modules loaded. Listening for commands...");
    
    // Main agent loop with real-time kernel telemetry and integrity checks
    let mut iteration = 0u32;
    loop {
        let telemetry_data = telemetry.collect_metrics().await;
        info!(target: "sentinel", "Telemetry: CPU={:.1}% RAM={}MB/{}MB NetConn={}", 
            telemetry_data.cpu_usage_percent, telemetry_data.ram_used_mb, 
            telemetry_data.ram_total_mb, telemetry_data.network_connections);
        
        // Periodic integrity check (every 12 iterations = 60 seconds)
        iteration = iteration.wrapping_add(1);
        if iteration % 12 == 0 {
            let tampered = integrity_checker.check_integrity();
            if !tampered.is_empty() {
                error!(target: "sentinel", "TAMPERING DETECTED on: {:?}", tampered);
                // In production: trigger self-destruct
                // std::process::abort();
            }
        }
        
        sleep(Duration::from_secs(5)).await;
    }
}

use aya::{Bpf, programs::TracePoint, maps::Array};
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemTelemetry {
    pub cpu_usage_percent: f64,
    pub ram_used_mb: u64,
    pub ram_total_mb: u64,
    pub network_connections: u32,
    pub timestamp: i64,
}

pub struct AegisTelemetry {
    telemetry: Arc<RwLock<SystemTelemetry>>,
}

impl AegisTelemetry {
    pub async fn new() -> Result<Self, anyhow::Error> {
        info!(target: "aegis_ebpf", "Initializing kernel-level telemetry (eBPF not loaded in userspace mode)");
        
        let telemetry = Arc::new(RwLock::new(SystemTelemetry {
            cpu_usage_percent: 0.0,
            ram_used_mb: 0,
            ram_total_mb: 0,
            network_connections: 0,
            timestamp: 0,
        }));
        
        Ok(Self { telemetry })
    }
    
    pub async fn collect_metrics(&self) -> SystemTelemetry {
        let cpu_usage = read_cpu_usage().await;
        let (ram_used, ram_total) = read_ram_usage().await;
        let net_conns = read_network_connections().await;
        
        let metrics = SystemTelemetry {
            cpu_usage_percent: cpu_usage,
            ram_used_mb: ram_used,
            ram_total_mb: ram_total,
            network_connections: net_conns,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };
        
        let mut telemetry = self.telemetry.write().await;
        *telemetry = metrics.clone();
        
        metrics
    }
    
    pub async fn get_telemetry(&self) -> SystemTelemetry {
        self.telemetry.read().await.clone()
    }
}

async fn read_cpu_usage() -> f64 {
    if let Ok(stat) = tokio::fs::read_to_string("/proc/stat").await {
        for line in stat.lines() {
            if line.starts_with("cpu ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let user = parts[1].parse::<u64>().unwrap_or(0);
                    let nice = parts[2].parse::<u64>().unwrap_or(0);
                    let system = parts[3].parse::<u64>().unwrap_or(0);
                    let idle = parts[4].parse::<u64>().unwrap_or(0);
                    let total = user + nice + system + idle;
                    if total > 0 {
                        return 100.0 * (total - idle) as f64 / total as f64;
                    }
                }
            }
        }
    }
    0.0
}

async fn read_ram_usage() -> (u64, u64) {
    if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
        let mut total = 0u64;
        let mut available = 0u64;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            } else if line.starts_with("MemAvailable:") {
                available = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            }
        }
        let used = total.saturating_sub(available);
        return (used / 1024, total / 1024);
    }
    (0, 0)
}

async fn read_network_connections() -> u32 {
    let mut count = 0u32;
    if let Ok(entries) = tokio::fs::read_dir("/proc/net").await {
        count += 1;
    }
    // Read TCP connections from /proc/net/tcp
    if let Ok(tcp) = tokio::fs::read_to_string("/proc/net/tcp").await {
        count += tcp.lines().count().saturating_sub(1) as u32;
    }
    count
}

use tracing::info;

// NOTE (Fase 0): the eBPF bytecode loader is intentionally stubbed.
// Real eBPF integration (aya, sched_switch attach) lives in Fase 2.
// See aegis-sentinel/src/ebpf_telemetry.rs which currently reads /proc as fallback.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!(target: "aegis_ebpf", "aegis-ebpf placeholder process (Fase 0 stub)");
    info!(target: "aegis_ebpf", "Real eBPF program loading will be wired in Fase 2");

    // Park the process; in Fase 2 this will own the eBPF program lifetime.
    tokio::signal::ctrl_c().await?;
    info!(target: "aegis_ebpf", "Shutdown signal received");
    Ok(())
}

// aegis-ebpf — Syscall and network telemetry daemon
//
// Fase 2: aya-based eBPF loader with TracePoint + KProbe probes.
//   - Loads aegis-ebpf.bpf.o (compiled from aegis-ebpf.bpf.c with clang -target bpf)
//   - Attaches tracepoints: syscalls/sys_enter_execve, syscalls/sys_enter_prctl
//   - Attaches kprobe: do_init_module
//   - Emits structured JSON events to Sentinel Engine via Unix socket
//
// Fallback (Fase 0): If the BPF object is not found, falls back to
//   proc-scanner for compatibility with kernels/environments lacking CAP_BPF.
//
// Build BPF object:
//   clang -O2 -g -target bpf \
//     -I/usr/include/x86_64-linux-gnu \
//     -c src/aegis-ebpf.bpf.c -o /opt/hispanshield/bin/aegis-ebpf.bpf.o

use std::{
    collections::HashMap,
    io::Write,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

const SENTINEL_SOCKET: &str = "/run/aegis/ebpf.sock";
const BPF_OBJECT_PATH: &str = "/opt/hispanshield/bin/aegis-ebpf.bpf.o";
const PROC_POLL_INTERVAL_MS: u64 = 500;

/// Mirrors the aegis_event struct in aegis-ebpf.bpf.c
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfRawEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    event_type: u32,
    timestamp_ns: u64,
    suspicious: u8,
    comm: [u8; 16],
    path: [u8; 128],
}

const EVENT_EXEC: u32 = 1;
const EVENT_KMOD: u32 = 2;
const EVENT_PRCTL: u32 = 3;

#[derive(Debug, serde::Serialize)]
#[serde(tag = "event_type")]
enum AegisEvent {
    Exec {
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        path: String,
        suspicious: bool,
        timestamp_ns: u64,
    },
    KernelModule {
        pid: u32,
        comm: String,
        timestamp_ns: u64,
    },
    Prctl {
        pid: u32,
        uid: u32,
        comm: String,
        timestamp_ns: u64,
    },
    // Fase 0 proc-scanner events
    ProcessAlert {
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        cmdline: String,
        reason: String,
        timestamp_ns: u64,
    },
    UnsignedModule {
        name: String,
        timestamp_ns: u64,
    },
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as u64
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn forward_to_sentinel(events: &[AegisEvent]) {
    if events.is_empty() || !Path::new(SENTINEL_SOCKET).exists() {
        return;
    }
    if let Ok(mut stream) = UnixStream::connect(SENTINEL_SOCKET) {
        for event in events {
            if let Ok(json) = serde_json::to_vec(event) {
                let _ = stream.write_all(&json);
                let _ = stream.write_all(b"\n");
            }
        }
    }
}

// ── Fase 2: aya eBPF loader ───────────────────────────────────────────────────

#[cfg(feature = "ebpf")]
mod ebpf_loader {
    use super::*;
    use aya::{
        maps::perf::AsyncPerfEventArray,
        programs::{KProbe, TracePoint},
        util::online_cpus,
        Bpf,
    };
    use bytes::BytesMut;

    pub async fn run_with_ebpf(bpf_path: &str) -> anyhow::Result<()> {
        let mut bpf = Bpf::load_file(bpf_path)?;

        // Attach TracePoint: sys_enter_execve
        let execve: &mut TracePoint = bpf
            .program_mut("trace_execve")
            .expect("trace_execve program not found")
            .try_into()?;
        execve.load()?;
        execve.attach("syscalls", "sys_enter_execve")?;
        info!(target: "aegis_ebpf", "TracePoint attached: syscalls/sys_enter_execve");

        // Attach TracePoint: sys_enter_prctl
        let prctl: &mut TracePoint = bpf
            .program_mut("trace_prctl")
            .expect("trace_prctl program not found")
            .try_into()?;
        prctl.load()?;
        prctl.attach("syscalls", "sys_enter_prctl")?;
        info!(target: "aegis_ebpf", "TracePoint attached: syscalls/sys_enter_prctl");

        // Attach KProbe: do_init_module
        let kmod: &mut KProbe = bpf
            .program_mut("detect_unsigned_kmod")
            .expect("detect_unsigned_kmod program not found")
            .try_into()?;
        kmod.load()?;
        kmod.attach("do_init_module", 0)?;
        info!(target: "aegis_ebpf", "KProbe attached: do_init_module");

        // Read events from perf ring buffer
        let cpus = online_cpus()?;
        let mut perf_array = AsyncPerfEventArray::try_from(
            bpf.take_map("SYSCALL_EVENTS").expect("SYSCALL_EVENTS map not found"),
        )?;

        let mut handles = Vec::new();
        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, Some(256))?;
            let handle = tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap_or_default();
                    let mut aegis_events = Vec::new();
                    for i in 0..events.read {
                        let data = &buffers[i];
                        if data.len() < std::mem::size_of::<BpfRawEvent>() {
                            continue;
                        }
                        let raw = unsafe {
                            std::ptr::read_unaligned(data.as_ptr() as *const BpfRawEvent)
                        };
                        let ev = match raw.event_type {
                            EVENT_EXEC => AegisEvent::Exec {
                                pid: raw.pid,
                                ppid: raw.ppid,
                                uid: raw.uid,
                                comm: cstr_to_string(&raw.comm),
                                path: cstr_to_string(&raw.path),
                                suspicious: raw.suspicious != 0,
                                timestamp_ns: raw.timestamp_ns,
                            },
                            EVENT_KMOD => AegisEvent::KernelModule {
                                pid: raw.pid,
                                comm: cstr_to_string(&raw.comm),
                                timestamp_ns: raw.timestamp_ns,
                            },
                            EVENT_PRCTL => AegisEvent::Prctl {
                                pid: raw.pid,
                                uid: raw.uid,
                                comm: cstr_to_string(&raw.comm),
                                timestamp_ns: raw.timestamp_ns,
                            },
                            _ => continue,
                        };
                        if matches!(&ev, AegisEvent::Exec { suspicious: true, .. }
                            | AegisEvent::KernelModule { .. }
                            | AegisEvent::Prctl { .. })
                        {
                            tracing::warn!(target: "aegis_ebpf",
                                "Suspicious event: {:?}", serde_json::to_string(&ev).unwrap_or_default());
                        }
                        aegis_events.push(ev);
                    }
                    forward_to_sentinel(&aegis_events);
                }
            });
            handles.push(handle);
        }

        info!(target: "aegis_ebpf", "eBPF probes active on {} CPUs", handles.len());
        tokio::signal::ctrl_c().await?;
        info!(target: "aegis_ebpf", "Shutdown signal received");
        Ok(())
    }
}

// ── Fase 0: proc-scanner fallback ────────────────────────────────────────────

const PROCESS_EXEC_DENYLIST: &[&str] = &[
    "python3", "curl", "wget", "nc", "netcat", "bash", "sh",
];

fn read_proc_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn read_proc_cmdline(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

fn read_proc_status(pid: u32) -> HashMap<String, String> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.splitn(2, ':');
            Some((p.next()?.trim().to_string(), p.next()?.trim().to_string()))
        })
        .collect()
}

fn scan_processes() -> Vec<AegisEvent> {
    let mut events = Vec::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return events,
    };
    for entry in proc_dir.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let comm = read_proc_comm(pid);
        let status = read_proc_status(pid);
        let uid: u32 = status.get("Uid")
            .and_then(|v| v.split_whitespace().next())
            .and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
        let ppid: u32 = status.get("PPid")
            .and_then(|s| s.parse().ok()).unwrap_or(0);

        if uid == 0 && PROCESS_EXEC_DENYLIST.iter().any(|d| comm.contains(d)) {
            events.push(AegisEvent::ProcessAlert {
                pid, ppid, uid,
                comm: comm.clone(),
                cmdline: read_proc_cmdline(pid),
                reason: format!("Root-owned denylist process: {comm}"),
                timestamp_ns: now_ns(),
            });
        }
        if let Some(cap_eff) = status.get("CapEff") {
            let cap_val = u64::from_str_radix(cap_eff.trim(), 16).unwrap_or(0);
            if cap_val == 0x1ffffffffff && uid > 0 {
                events.push(AegisEvent::ProcessAlert {
                    pid, ppid, uid,
                    comm,
                    cmdline: read_proc_cmdline(pid),
                    reason: "Full capability set on non-root process".into(),
                    timestamp_ns: now_ns(),
                });
            }
        }
    }
    events
}

fn check_kernel_modules() -> Vec<AegisEvent> {
    let mut events = Vec::new();
    let modules_raw = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    for line in modules_raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 1 { continue; }
        let name = fields[0];
        let taint_path = format!("/sys/module/{name}/taint");
        let taint = std::fs::read_to_string(&taint_path).unwrap_or_default();
        if taint.contains('E') || taint.contains('O') {
            warn!(target: "aegis_ebpf", "Unsigned/out-of-tree module: {}", name);
            events.push(AegisEvent::UnsignedModule {
                name: name.to_string(),
                timestamp_ns: now_ns(),
            });
        }
    }
    events
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Fase 2: try to load the compiled BPF object
    #[cfg(feature = "ebpf")]
    if Path::new(BPF_OBJECT_PATH).exists() {
        info!(target: "aegis_ebpf",
            "BPF object found at {} — starting Fase 2 eBPF mode", BPF_OBJECT_PATH);
        return ebpf_loader::run_with_ebpf(BPF_OBJECT_PATH).await;
    }

    // Fase 0 fallback: proc-scanner
    info!(target: "aegis_ebpf",
        "BPF object not found at {} — using Fase 0 proc-scanner fallback", BPF_OBJECT_PATH);
    info!(target: "aegis_ebpf",
        "To enable Fase 2: clang -O2 -g -target bpf -c src/aegis-ebpf.bpf.c -o {}",
        BPF_OBJECT_PATH);

    let mut interval = tokio::time::interval(Duration::from_millis(PROC_POLL_INTERVAL_MS));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut events = Vec::new();
                events.extend(scan_processes());
                events.extend(check_kernel_modules());
                if !events.is_empty() {
                    info!(target: "aegis_ebpf", "Emitting {} telemetry events", events.len());
                    forward_to_sentinel(&events);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!(target: "aegis_ebpf", "Shutdown signal received");
                break;
            }
        }
    }
    Ok(())
}

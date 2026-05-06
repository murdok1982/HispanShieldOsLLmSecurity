# aegis-ebpf — Real eBPF integration roadmap

Fase 0 made this crate compile (placeholder bin). The two integration steps below
are the actual work to ship genuine kernel-level telemetry. They are deliberately
deferred out of the Phase 2 hardening commit because they require an out-of-tree
toolchain (bpf-linker) that the CI runner does not yet pin.

## Step A — Author the eBPF program

Add a sibling crate `aegis-ebpf-bytecode/` (members entry in
`core/rust/Cargo.toml`):

```
[package]
name = "aegis-ebpf-bytecode"
edition = "2021"

[[bin]]
name = "aegis-ebpf-bytecode"
path = "src/main.rs"

[dependencies]
aya-ebpf = "0.13"
aya-log-ebpf = "0.13"
```

The bytecode crate is `#![no_std]`, attaches to `tracepoint:sched:sched_switch`,
and writes per-CPU run-queue length into a `Array<u64>` map.

## Step B — Wire the loader

In `aegis-ebpf/src/main.rs` (replace the Fase 0 stub):

```rust
let bytes = include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/aegis-ebpf-bytecode")
);
let mut bpf = aya::Ebpf::load(bytes)?;
let prog: &mut aya::programs::TracePoint = bpf
    .program_mut("aegis_telemetry").unwrap().try_into()?;
prog.load()?;
prog.attach("sched", "sched_switch")?;
```

`build.rs` invokes `cargo build -p aegis-ebpf-bytecode --target bpfel-unknown-none`
and copies the output into `OUT_DIR` so `include_bytes_aligned!` finds it.

## CI wiring

`rustup target add bpfel-unknown-none` plus `cargo install bpf-linker` are added
to the CI image. Until that lands, `aegis-sentinel/src/ebpf_telemetry.rs`
continues to read `/proc/{stat,meminfo,net/tcp}` as a documented fallback.

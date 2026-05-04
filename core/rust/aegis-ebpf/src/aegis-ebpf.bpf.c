#![no_std]
#![no_main]

use aya_bpf::{macros::map, maps::Array, programs::TracePointContext};
use aya_log_ebpf::info;

#[map]
static mut CPU_USAGE: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static mut RAM_USAGE: Array<u64> = Array::with_max_entries(1, 0);

#[aya_bpf::program(name = "aegis_telemetry")]
pub fn aegis_telemetry(ctx: TracePointContext) -> i64 {
    match try_aegis_telemetry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_aegis_telemetry(ctx: TracePointContext) -> Result<i64, i64> {
    let cpu_id = unsafe { aya_bpf::helpers::bpf_get_smp_processor_id() } as u32;
    
    // Log telemetry event
    info!(&ctx, "Aegis eBPF telemetry: CPU sampling on cpu={}", cpu_id);
    
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

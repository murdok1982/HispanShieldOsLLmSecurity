use aya::programs::KProbe;

pub fn attach_execve_probe() -> Result<(), Box<dyn std::error::Error>> {
    // let mut prog = KProbe::load(&EBPF_PROGRAM)?;
    // prog.attach("sys_execve", 0)?;  // Hook en syscall crítico
    // Enviar evento a userspace vía perf buffer
    Ok(())
}

// Integrar con sentinel para correlación:
// execve + connect + network flow = detección de C2

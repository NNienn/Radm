// aggregator/src/bpf_loader.rs

use crate::config::AggregatorConfig;
use anyhow::Result;

#[cfg(unix)]
use aya::{
    Bpf, BpfLoader,
    programs::{Xdp, XdpFlags, TracePoint},
};
#[cfg(unix)]
use anyhow::Context;

#[cfg(unix)]
pub struct LoadedBpf {
    pub bpf_tp:  Bpf,   // tracepoints
    pub bpf_tc:  Bpf,   // TC BPF
    pub bpf_xdp: Bpf,   // XDP
}

#[cfg(unix)]
pub fn load_and_attach(cfg: &AggregatorConfig) -> Result<LoadedBpf> {
    std::fs::create_dir_all("/sys/fs/bpf/radm")
        .context("create BPF pin directory")?;

    // ── Tracepoint object ──────────────────────────────────────────────
    let mut bpf_tp = BpfLoader::new()
        .load_file(format!("{}/radm_tp.o", cfg.bpf_object_path))
        .context("load radm_tp.o")?;

    for hook in &["mprotect", "mmap", "ptrace", "memfd"] {
        let prog_name = format!("radm_{}", hook);
        let prog: &mut TracePoint = bpf_tp
            .program_mut(&prog_name)
            .context(format!("find program {}", prog_name))?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", &format!("sys_enter_{}", hook))
            .context(format!("attach tracepoint sys_enter_{}", hook))?;
    }

    // ── XDP object ────────────────────────────────────────────────────
    let mut bpf_xdp = BpfLoader::new()
        .load_file(format!("{}/radm_xdp.o", cfg.bpf_object_path))
        .context("load radm_xdp.o")?;

    let xdp_prog: &mut Xdp = bpf_xdp
        .program_mut("radm_xdp")
        .context("find radm_xdp program")?
        .try_into()?;
    xdp_prog.load()?;
    xdp_prog.attach(&cfg.host_interface, XdpFlags::default())
        .context(format!("attach XDP to {}", cfg.host_interface))?;

    // TC object loaded but NOT attached here — the veth_manager attaches
    // per-container as containers are discovered.
    let bpf_tc = BpfLoader::new()
        .load_file(format!("{}/radm_tc.o", cfg.bpf_object_path))
        .context("load radm_tc.o")?;

    Ok(LoadedBpf { bpf_tp, bpf_tc, bpf_xdp })
}

#[cfg(not(unix))]
pub struct LoadedBpf {}

#[cfg(not(unix))]
pub fn load_and_attach(_cfg: &AggregatorConfig) -> Result<LoadedBpf> {
    tracing::warn!("eBPF is only supported on Unix/Linux. Mocking BPF loader.");
    Ok(LoadedBpf {})
}

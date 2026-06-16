// mitigation/src/bpf_updater.rs

use std::path::Path;

#[cfg(unix)]
pub fn update_quarantine_maps(
    bpf_pin_dir: &Path,
    cgroup_id: u64,
    ip_addr: Option<u32>,
) -> anyhow::Result<()> {
    use aya::maps::HashMap as AyaHashMap;

    // Update quarantine_map (cgroup_id -> 1)
    let qmap_path = bpf_pin_dir.join("quarantine_map");
    if qmap_path.exists() {
        let mut qmap = unsafe { AyaHashMap::<_, u64, u8>::from_pinned(&qmap_path)? };
        qmap.insert(cgroup_id, 1u8, 0)?;
    }

    // Update quarantine_ip_map (ip_addr -> 1)
    if let Some(ip) = ip_addr {
        let qipmap_path = bpf_pin_dir.join("quarantine_ip_map");
        if qipmap_path.exists() {
            let mut qipmap = unsafe { AyaHashMap::<_, u32, u8>::from_pinned(&qipmap_path)? };
            qipmap.insert(ip, 1u8, 0)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn update_quarantine_maps(
    _bpf_pin_dir: &Path,
    _cgroup_id: u64,
    _ip_addr: Option<u32>,
) -> anyhow::Result<()> {
    tracing::warn!("BPF updates are only supported on Unix targets. Mocking map update.");
    Ok(())
}

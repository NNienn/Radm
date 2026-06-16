// aggregator/src/cgroup_resolver.rs

use std::sync::Arc;
use dashmap::DashMap;
use tracing::{error, info, debug};
use std::time::Duration;

pub struct CgroupResolver {
    cgroup_map: Arc<DashMap<u64, (String, u32)>>,
    pid_cgmap_pin: String,
}

impl CgroupResolver {
    pub fn new(cgroup_map: Arc<DashMap<u64, (String, u32)>>, pid_cgmap_pin: &str) -> Self {
        Self {
            cgroup_map,
            pid_cgmap_pin: pid_cgmap_pin.to_string(),
        }
    }

    pub async fn start_resolver(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            if let Err(e) = self.resolve_cgroups() {
                debug!("Cgroup resolution tick details: {}", e);
            }
        }
    }

    #[cfg(unix)]
    fn resolve_cgroups(&self) -> anyhow::Result<()> {
        use std::fs;
        use std::path::Path;
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;
        use aya::maps::HashMap as AyaHashMap;

        let mut active_mappings = HashMap::new();

        // Walk /proc to find all numeric directories (PIDs)
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    if let Ok(cgroup_id) = self.get_cgroup_id_for_pid(pid) {
                        if let Ok(container_id) = self.get_container_id_for_pid(pid) {
                            active_mappings.insert(pid, (cgroup_id, container_id));
                        }
                    }
                }
            }
        }

        // Update the BPF map if it's pinned
        let pid_cgmap_path = Path::new(&self.pid_cgmap_pin);
        if pid_cgmap_path.exists() {
            if let Ok(mut bpf_map) = unsafe { AyaHashMap::<_, u32, u64>::from_pinned(pid_cgmap_path) } {
                for (&pid, &(cgroup_id, _)) in &active_mappings {
                    let _ = bpf_map.insert(pid, cgroup_id, 0);
                }
            }
        }

        // Update the DashMap in userspace
        for (&pid, &(cgroup_id, ref container_id)) in &active_mappings {
            self.cgroup_map.insert(cgroup_id, (container_id.clone(), pid));
        }

        Ok(())
    }

    #[cfg(unix)]
    fn get_cgroup_id_for_pid(&self, pid: u32) -> anyhow::Result<u64> {
        use std::fs;
        use std::os::unix::fs::MetadataExt;

        let cgroup_content = fs::read_to_string(format!("/proc/{}/cgroup", pid))?;
        for line in cgroup_content.lines() {
            if line.starts_with("0::") {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    let path = parts[2];
                    let full_path = format!("/sys/fs/cgroup{}", path);
                    let metadata = fs::metadata(&full_path)?;
                    return Ok(metadata.ino());
                }
            }
        }
        anyhow::bail!("cgroup v2 path not found for pid {}", pid)
    }

    #[cfg(unix)]
    fn get_container_id_for_pid(&self, pid: u32) -> anyhow::Result<String> {
        use std::fs;

        let cgroup_content = fs::read_to_string(format!("/proc/{}/cgroup", pid))?;
        for line in cgroup_content.lines() {
            if line.contains("docker") || line.contains("containerd") || line.contains("kubepods") {
                if let Some(container_id) = extract_container_id(line) {
                    return Ok(container_id);
                }
            }
        }
        Ok(format!("pid:{}", pid))
    }

    #[cfg(not(unix))]
    fn resolve_cgroups(&self) -> anyhow::Result<()> {
        // Stub mapping for development compilation on Windows
        // Ingest a mock container
        self.cgroup_map.insert(0x12345678, ("mock-container-id".to_string(), 9999));
        Ok(())
    }
}

#[cfg(unix)]
fn extract_container_id(s: &str) -> Option<String> {
    let mut current_hex = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            current_hex.push(c);
        } else {
            if current_hex.len() == 64 {
                return Some(current_hex);
            }
            current_hex.clear();
        }
    }
    if current_hex.len() == 64 {
        Some(current_hex)
    } else {
        None
    }
}

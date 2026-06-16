// mitigation/src/quarantine_exec.rs

use std::path::PathBuf;
use crate::proto::radm::{AnomalyAlert, QuarantineEvent, QuarantineStatus};

pub struct QuarantineExecutor {
    bpf_pin_dir:       PathBuf,  // /sys/fs/bpf/radm/
    tc_drop_bpf_obj:   PathBuf,  // path to compiled radm_tc.o
    forensic_dir:      PathBuf,  // /var/radm/forensics/
}

impl QuarantineExecutor {
    pub fn new(bpf_pin_dir: &str, tc_bpf_obj: &str, forensic_dir: &str) -> Self {
        Self {
            bpf_pin_dir:     PathBuf::from(bpf_pin_dir),
            tc_drop_bpf_obj: PathBuf::from(tc_bpf_obj),
            forensic_dir:    PathBuf::from(forensic_dir),
        }
    }

    #[cfg(unix)]
    pub async fn quarantine(&self, alert: &AnomalyAlert) -> QuarantineEvent {
        use nix::unistd::Pid;
        use tracing::{info, warn, error};
        use crate::forensics::capture_memory;

        let pid = alert.target_pid;
        let cgroup_id = alert.cgroup_id;

        info!(
            "Quarantine initiated: container={} pid={} cgroup={:#x}",
            alert.container_id, pid, cgroup_id
        );

        // ── Step 1: Find the veth pair ──────────────────────────────────────
        let veth_host = match self.find_veth_for_pid(pid) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to find veth for pid {}: {}", pid, e);
                return self.failed_event(alert, &e.to_string());
            }
        };

        // ── Step 2: Attach TC BPF DROP to veth host side ───────────────────
        if let Err(e) = self.attach_tc_drop(&veth_host) {
            error!("TC attach failed for {}: {}", veth_host, e);
            return self.failed_event(alert, &e.to_string());
        }

        // ── Step 3: Update BPF quarantine maps ─────────────────────────────
        if let Err(e) = self.update_bpf_quarantine_maps(cgroup_id, pid) {
            warn!("BPF map update failed (non-fatal): {}", e);
        }

        // ── Step 4: Async forensic capture ─────────────────────────────────
        let forensic_path = self.forensic_dir.join(format!(
            "forensic_{}_pid{}.bin.enc",
            chrono_or_timestamp(),
            pid,
        ));
        let forensic_path_str = forensic_path.to_string_lossy().to_string();
        let fp_clone = forensic_path.clone();
        tokio::spawn(async move {
            if let Err(e) = capture_memory(Pid::from_raw(pid as i32), &fp_clone).await {
                warn!("Forensic capture failed: {}", e);
            }
        });

        info!("Quarantine ACTIVE: veth={} forensic={}", veth_host, forensic_path_str);

        QuarantineEvent {
            alert_id:      alert.alert_id,
            timestamp_ns:  current_time_ns(),
            container_id:  alert.container_id.clone(),
            target_pid:    pid,
            status:        QuarantineStatus::Active as i32,
            veth_iface:    veth_host,
            forensic_path: forensic_path_str,
            error_msg:     String::new(),
        }
    }

    #[cfg(unix)]
    fn find_veth_for_pid(&self, pid: u32) -> anyhow::Result<String> {
        use std::process::Command;
        
        let netns_path = format!("/proc/{}/ns/net", pid);

        let out = Command::new("nsenter")
            .args([
                &format!("--net={}", netns_path),
                "--",
                "cat",
                "/sys/class/net/eth0/ifindex",
            ])
            .output()?;

        let container_ifindex: u32 = String::from_utf8(out.stdout)?
            .trim()
            .parse()?;

        let entries = std::fs::read_dir("/sys/class/net")?;
        for entry in entries {
            let entry = entry?;
            let iface = entry.file_name();
            let iface_name = iface.to_string_lossy();
            let iflink_path = format!("/sys/class/net/{}/iflink", iface_name);

            if let Ok(iflink_str) = std::fs::read_to_string(&iflink_path) {
                if let Ok(iflink) = iflink_str.trim().parse::<u32>() {
                    if iflink == container_ifindex {
                        return Ok(iface_name.to_string());
                    }
                }
            }
        }

        anyhow::bail!("No host-side veth found for container ifindex {}", container_ifindex)
    }

    #[cfg(unix)]
    fn attach_tc_drop(&self, veth: &str) -> anyhow::Result<()> {
        use std::process::Command;

        let obj_path = self.tc_drop_bpf_obj.to_string_lossy();

        let _ = Command::new("tc")
            .args(["qdisc", "add", "dev", veth, "clsact"])
            .output();

        let status = Command::new("tc")
            .args([
                "filter", "replace", "dev", veth, "ingress",
                "bpf", "da", "obj", &obj_path, "sec", "tc/ingress",
            ])
            .status()?;
        anyhow::ensure!(status.success(), "tc filter ingress attach failed");

        let status = Command::new("tc")
            .args([
                "filter", "replace", "dev", veth, "egress",
                "bpf", "da", "obj", &obj_path, "sec", "tc/egress",
            ])
            .status()?;
        anyhow::ensure!(status.success(), "tc filter egress attach failed");

        Ok(())
    }

    #[cfg(unix)]
    fn update_bpf_quarantine_maps(&self, cgroup_id: u64, pid: u32) -> anyhow::Result<()> {
        // Delegate to BPF updater to update maps programmatically
        if let Err(e) = crate::bpf_updater::update_quarantine_maps(&self.bpf_pin_dir, cgroup_id, None) {
            tracing::warn!("BPF updater failed: {}. Falling back to bpftool.", e);
            // Fallback to bpftool if updater fails
            use std::process::Command;
            let cmap = self.bpf_pin_dir.join("quarantine_map").to_string_lossy().to_string();
            let key_hex  = format!("{:#018x}", cgroup_id);
            let value = "0x01";

            let status = Command::new("bpftool")
                .args(["map", "update", "pinned", &cmap,
                       "key", &key_hex, "value", value])
                .status()?;
            anyhow::ensure!(status.success(), "bpftool map update quarantine_map failed");
        }
        Ok(())
    }

    #[cfg(unix)]
    fn failed_event(&self, alert: &AnomalyAlert, msg: &str) -> QuarantineEvent {
        QuarantineEvent {
            alert_id:      alert.alert_id,
            timestamp_ns:  current_time_ns(),
            container_id:  alert.container_id.clone(),
            target_pid:    alert.target_pid,
            status:        QuarantineStatus::Failed as i32,
            veth_iface:    String::new(),
            forensic_path: String::new(),
            error_msg:     msg.to_string(),
        }
    }

    #[cfg(not(unix))]
    pub async fn quarantine(&self, alert: &AnomalyAlert) -> QuarantineEvent {
        tracing::warn!("Quarantine execution is only supported on Unix targets. Mocking quarantine.");
        QuarantineEvent {
            alert_id:      alert.alert_id,
            timestamp_ns:  current_time_ns(),
            container_id:  alert.container_id.clone(),
            target_pid:    alert.target_pid,
            status:        QuarantineStatus::Active as i32,
            veth_iface:    "mock-veth".to_string(),
            forensic_path: "mock-forensic-path".to_string(),
            error_msg:     String::new(),
        }
    }
}

fn current_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn chrono_or_timestamp() -> String {
    let ns = current_time_ns();
    format!("{}", ns / 1_000_000_000)
}

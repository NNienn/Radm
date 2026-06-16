// mitigation/src/main.rs

mod config;
mod quarantine_exec;
mod forensics;
mod bpf_updater;
pub mod proto {
    pub mod radm {
        include!("proto/radm.v1.rs");
    }
}

use tokio::net::UnixStream;
use tokio::io::AsyncReadExt;
use prost::Message;
use tracing::{error, info, warn};
use crate::proto::radm::AnomalyAlert;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = config::load_config("radm.toml").unwrap_or_default();

    let executor = quarantine_exec::QuarantineExecutor::new(
        &cfg.bpf_pin_dir,
        &cfg.tc_bpf_obj,
        &cfg.forensic_dir,
    );

    loop {
        info!("Connecting to alert UDS socket at {}...", cfg.alert_socket_path);
        match UnixStream::connect(&cfg.alert_socket_path).await {
            Ok(mut stream) => {
                info!("Connected to alert socket!");
                let mut len_buf = [0u8; 4];
                loop {
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        warn!("Alert socket disconnected");
                        break;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut body_buf = vec![0u8; len];
                    if stream.read_exact(&mut body_buf).await.is_err() {
                        warn!("Failed to read alert body");
                        break;
                    }

                    if let Ok(alert) = AnomalyAlert::decode(&body_buf[..]) {
                        info!("Received anomaly alert for cgroup={:#x}", alert.cgroup_id);
                        if cfg.auto_quarantine {
                            let event = executor.quarantine(&alert).await;
                            info!("Quarantine executed: status={:?}, forensics={:?}, error={:?}", 
                                  event.status, event.forensic_path, event.error_msg);
                        } else {
                            info!("Auto-quarantine is disabled. Observe mode only.");
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to alert socket: {}. Reconnecting in 3s...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }
    }
}

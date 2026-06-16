// aggregator/src/quarantine_receiver.rs

use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use prost::Message;
use tracing::{error, info, warn};
use dashmap::DashMap;

use crate::config::AggregatorConfig;
use crate::proto::radm::AnomalyAlert;

pub async fn run_alert_receiver(
    socket_path: &str,
    _cfg: &AggregatorConfig,
    cgroup_map: Arc<DashMap<u64, (String, u32)>>,
) -> anyhow::Result<()> {
    // Remove stale socket
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    info!("Alert receiver listening on {}", socket_path);

    let (tx, _) = broadcast::channel::<bytes::Bytes>(32);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx_clone = tx.clone();
                let rx_clone = tx.subscribe();
                let cgroup_map_clone = cgroup_map.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_alert_connection(stream, tx_clone, rx_clone, cgroup_map_clone).await {
                        warn!("Connection handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting alert connection: {}", e);
            }
        }
    }
}

async fn handle_alert_connection(
    stream: UnixStream,
    tx: broadcast::Sender<bytes::Bytes>,
    mut rx: broadcast::Receiver<bytes::Bytes>,
    cgroup_map: Arc<DashMap<u64, (String, u32)>>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    // Read loop for incoming alerts
    let tx_clone = tx.clone();
    let read_task = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            if reader.read_exact(&mut len_buf).await.is_err() {
                break; // connection closed
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body_buf = vec![0u8; len];
            if reader.read_exact(&mut body_buf).await.is_err() {
                break;
            }

            // Parse AnomalyAlert
            if let Ok(mut alert) = AnomalyAlert::decode(&body_buf[..]) {
                // Enrich alert using cgroup_map
                if let Some(info) = cgroup_map.get(&alert.cgroup_id) {
                    let (container_id, pid) = info.value();
                    alert.container_id = container_id.clone();
                    alert.container_name = container_id.clone();
                    alert.target_pid = *pid;
                }

                // Re-encode enriched alert
                let mut enriched_buf = Vec::with_capacity(alert.encoded_len() + 4);
                let enriched_len = alert.encoded_len() as u32;
                enriched_buf.extend_from_slice(&enriched_len.to_be_bytes());
                if alert.encode(&mut enriched_buf).is_ok() {
                    let _ = tx_clone.send(bytes::Bytes::from(enriched_buf));
                }
            }
        }
    });

    // Write loop for outgoing enriched alerts (broadcasting to mitigation)
    let write_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if writer.write_all(&msg).await.is_err() {
                        break; // connection closed
                      }
                  }
                  Err(broadcast::error::RecvError::Lagged(_)) => continue,
                  Err(_) => break,
              }
          }
      });

      // Wait for either loop to finish (e.g. client disconnects)
      tokio::select! {
          _ = read_task => {},
          _ = write_task => {},
      }

      Ok(())
  }

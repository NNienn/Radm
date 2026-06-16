// aggregator/src/ipc_server.rs
//
// Accepts connections on /run/radm/graph.sock and streams GraphSnapshot
// protobufs using a simple length-prefixed wire format:
//
//   [ 4-byte big-endian u32 message_length ][ message_length bytes ]
//
// Multiple consumers (e.g., inference engine) can connect simultaneously.

use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::proto::radm::GraphSnapshot;

pub async fn run_ipc_server(
    socket_path: &str,
    mut rx: tokio::sync::mpsc::Receiver<GraphSnapshot>,
) -> anyhow::Result<()> {
    // Clean up any stale socket file
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("Graph IPC server listening on {}", socket_path);

    // Broadcast channel so multiple readers get every snapshot
    let (bcast_tx, _bcast_rx) = broadcast::channel::<bytes::Bytes>(64);
    let bcast_tx_clone = bcast_tx.clone();

    // Forwarding task: mpsc → broadcast
    tokio::spawn(async move {
        while let Some(snapshot) = rx.recv().await {
            let mut buf = Vec::with_capacity(snapshot.encoded_len() + 4);
            let len = snapshot.encoded_len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            snapshot.encode(&mut buf).expect("protobuf encode");
            let _ = bcast_tx_clone.send(bytes::Bytes::from(buf));
        }
    });

    // Accept loop
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let mut bcast_rx = bcast_tx.subscribe();
                tokio::spawn(async move {
                    handle_client(stream, &mut bcast_rx).await;
                });
            }
            Err(e) => error!("IPC accept error: {}", e),
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    rx: &mut broadcast::Receiver<bytes::Bytes>,
) {
    loop {
        match rx.recv().await {
            Ok(frame) => {
                if stream.write_all(&frame).await.is_err() {
                    break;  // client disconnected
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Receiver is too slow — log and continue (don't disconnect)
                tracing::warn!("IPC consumer lagged {} messages", n);
            }
            Err(_) => break,
        }
    }
}

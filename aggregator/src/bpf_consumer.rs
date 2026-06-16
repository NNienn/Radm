// aggregator/src/bpf_consumer.rs

use crate::types::RadmEvent;
use tokio::sync::mpsc;

#[cfg(unix)]
use aya::maps::RingBuf;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
#[cfg(unix)]
use tracing::{debug, warn};

#[cfg(unix)]
pub async fn consume_ring_buffer(
    mut ring: RingBuf<Arc<aya::maps::MapData>>,
    tx: mpsc::Sender<RadmEvent>,
) -> anyhow::Result<()> {
    let async_fd = AsyncFd::new(ring)?;

    loop {
        let mut guard = async_fd.readable().await?;

        loop {
            match async_fd.get_mut().next() {
                Some(item) => {
                    if item.len() < std::mem::size_of::<RadmEvent>() {
                        warn!("short ring buffer item: {} bytes", item.len());
                        continue;
                    }
                    let event = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const RadmEvent)
                    };
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    debug!("consumed event cgroup={} pid={}", event.cgroup_id, event.pid);
                }
                None => break,
            }
        }

        guard.clear_ready();
    }
}

pub async fn consume_mock_ring_buffer(
    _tx: mpsc::Sender<RadmEvent>,
) -> anyhow::Result<()> {
    tracing::warn!("eBPF ring buffer consumer is only supported on Unix/Linux. Mocking consumer.");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

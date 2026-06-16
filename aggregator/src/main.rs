// aggregator/src/main.rs
//
// Thread pool architecture:
//   Pool A: BPF ring-buffer consumer      (tokio, 2 threads)
//   Pool B: Sliding-window graph builder   (tokio, 2 threads)
//   Pool C: IPC graph streamer             (tokio, 1 thread)
//   Pool D: cgroup_id resolver             (blocking, 1 thread via spawn_blocking)
//   Pool E: Quarantine command receiver    (tokio, 1 thread)

mod config;
mod graph_builder;
#[cfg(unix)]
mod bpf_consumer;
#[cfg(unix)]
mod bpf_loader;
#[cfg(unix)]
mod cgroup_resolver;
#[cfg(unix)]
mod ipc_server;
#[cfg(unix)]
mod quarantine_receiver;
pub mod proto {
    pub mod radm {
        include!("proto/radm.v1.rs");
    }
}
pub mod types;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::load_config("radm.toml").unwrap_or_default();

    // Shared cgroup resolver map
    let _cgroup_map: Arc<dashmap::DashMap<u64, (String, u32)>> = Arc::new(dashmap::DashMap::new());

    // Channels between pipeline stages
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(8192);
    let (snapshot_tx, snapshot_rx) = tokio::sync::mpsc::channel(32);

    #[cfg(unix)]
    {
        run_unix_pipeline(cfg, cgroup_map, event_tx, event_rx, snapshot_tx, snapshot_rx).await?;
    }

    #[cfg(not(unix))]
    {
        run_mock_pipeline(cfg, event_tx, event_rx, snapshot_tx, snapshot_rx).await?;
    }

    Ok(())
}

#[cfg(unix)]
async fn run_unix_pipeline(
    cfg: config::AggregatorConfig,
    cgroup_map: Arc<dashmap::DashMap<u64, (String, u32)>>,
    event_tx: tokio::sync::mpsc::Sender<types::RadmEvent>,
    event_rx: tokio::sync::mpsc::Receiver<types::RadmEvent>,
    snapshot_tx: tokio::sync::mpsc::Sender<crate::proto::radm::GraphSnapshot>,
    snapshot_rx: tokio::sync::mpsc::Receiver<crate::proto::radm::GraphSnapshot>,
) -> anyhow::Result<()> {
    // Load and attach eBPF programs
    let loaded = bpf_loader::load_and_attach(&cfg)?;

    // Pool A: ring buffer consumer
    // Extract ring buffer handle
    if let Ok(mut ring_map) = loaded.bpf_tp.map_mut("telemetry_ring") {
        if let Ok(ring) = aya::maps::RingBuf::try_from(&mut ring_map) {
            tokio::spawn(bpf_consumer::consume_ring_buffer(ring, event_tx));
        }
    }

    // Pool B: graph builder
    let window_ms = cfg.window_duration_ms;
    tokio::spawn(graph_builder::run_graph_builder(
        event_rx,
        snapshot_tx,
        window_ms,
        cfg.snapshot_interval_ms.max(1),
    ));

    // Pool C: IPC graph streamer
    let socket_path = cfg.graph_socket_path.clone();
    tokio::spawn(ipc_server::run_ipc_server(&socket_path, snapshot_rx));

    // Pool D: cgroup resolver
    let resolver = cgroup_resolver::CgroupResolver::new(cgroup_map.clone(), &cfg.pid_cgmap_pin);
    tokio::spawn(resolver.start_resolver());

    // Pool E: alert / quarantine receiver
    let alert_path = cfg.alert_socket_path.clone();
    tokio::spawn(quarantine_receiver::run_alert_receiver(&alert_path, &cfg, cgroup_map));

    // Keep main alive
    tokio::signal::ctrl_c().await?;
    tracing::info!("radm-aggregator shutting down");
    Ok(())
}

#[cfg(not(unix))]
async fn run_mock_pipeline(
    cfg: config::AggregatorConfig,
    event_tx: tokio::sync::mpsc::Sender<types::RadmEvent>,
    event_rx: tokio::sync::mpsc::Receiver<types::RadmEvent>,
    snapshot_tx: tokio::sync::mpsc::Sender<crate::proto::radm::GraphSnapshot>,
    mut snapshot_rx: tokio::sync::mpsc::Receiver<crate::proto::radm::GraphSnapshot>,
) -> anyhow::Result<()> {
    tracing::warn!("RADM is running in mock mode on a non-Unix host.");

    tokio::spawn(graph_builder::run_graph_builder(
        event_rx,
        snapshot_tx,
        cfg.window_duration_ms,
        cfg.snapshot_interval_ms.max(250),
    ));

    tokio::spawn(async move {
        let mut counter: u64 = 0;
        loop {
            let timestamp_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let event = types::RadmEvent {
                timestamp_ns,
                cgroup_id: 0xfeed_beef,
                pid: 1000,
                tgid: 1000,
                syscall_id: 1,
                src_ip: 0,
                dst_ip: 0,
                src_port: 0,
                dst_port: 0,
                memory_flags: 0x7,
                payload_hash: counter as u32,
                event_type: 1,
                ip_proto: 0,
            };
            counter = counter.wrapping_add(1);
            if event_tx.send(event).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });

    tokio::spawn(async move {
        while let Some(snapshot) = snapshot_rx.recv().await {
            tracing::info!(
                "mock snapshot seq={} nodes={} edges={}",
                snapshot.sequence_id,
                snapshot.nodes.len(),
                snapshot.edges.len()
            );
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("radm-aggregator mock shutdown");
    Ok(())
}

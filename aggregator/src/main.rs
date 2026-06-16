// aggregator/src/main.rs
//
// Thread pool architecture:
//   Pool A: BPF ring-buffer consumer      (tokio, 2 threads)
//   Pool B: Sliding-window graph builder   (tokio, 2 threads)
//   Pool C: IPC graph streamer             (tokio, 1 thread)
//   Pool D: cgroup_id resolver             (blocking, 1 thread via spawn_blocking)
//   Pool E: Quarantine command receiver    (tokio, 1 thread)

mod bpf_loader;
mod bpf_consumer;
mod config;
mod graph_builder;
mod ipc_server;
mod quarantine_receiver;
mod cgroup_resolver;
pub mod proto {
    pub mod radm {
        include!("proto/radm.v1.rs");
    }
}
pub mod types;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::load_config("radm.toml").unwrap_or_default();

    // Load and attach eBPF programs
    let loaded = bpf_loader::load_and_attach(&cfg)?;

    // Shared cgroup resolver map
    let cgroup_map = Arc::new(dashmap::DashMap::new());

    // Channels between pipeline stages
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(8192);
    let (snapshot_tx, snapshot_rx) = tokio::sync::mpsc::channel(32);

    // Pool A: ring buffer consumer
    #[cfg(unix)]
    {
        // Extract ring buffer handle
        if let Ok(mut ring_map) = loaded.bpf_tp.map_mut("telemetry_ring") {
            if let Ok(ring) = aya::maps::RingBuf::try_from(&mut ring_map) {
                tokio::spawn(bpf_consumer::consume_ring_buffer(ring, event_tx));
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(bpf_consumer::consume_mock_ring_buffer(event_tx));
    }

    // Pool B: graph builder
    let window_ms = cfg.window_duration_ms;
    tokio::spawn(graph_builder::run_graph_builder(
        event_rx,
        snapshot_tx,
        window_ms,
        window_ms / 5,  // emit snapshot at 5x the window rate
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

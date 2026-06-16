// aggregator/src/graph_builder.rs
//
// Maintains a 5-second sliding window over raw telemetry events and exports
// a GraphSnapshot protobuf every window_interval_ms milliseconds.

use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use crate::types::RadmEvent;
use crate::proto::radm::{GraphSnapshot, NodeFeatures, Edge as ProtoEdge};

const NODE_FEATURE_DIM: usize = 7;  // Must match Python model input_dim

#[derive(Debug, Default, Clone)]
struct NodeState {
    node_id:           u64,   // cgroup_id or IP hash
    node_type:         u32,   // NodeType enum
    label:             String,
    mprotect_count:    f32,
    packet_iat_sum:    f64,
    packet_iat_sqsum:  f64,
    packet_iat_count:  u64,
    last_packet_ns:    u64,
    unique_ports:      std::collections::HashSet<u16>,
    event_count:       f32,
}

impl NodeState {
    fn to_features(&self, window_secs: f32) -> Vec<f32> {
        // Feature vector (must match NODE_FEATURE_DIM = 7)
        let type_oh: Vec<f32> = match self.node_type {
            0 => vec![1.0, 0.0, 0.0],  // CONTAINER
            1 => vec![0.0, 1.0, 0.0],  // SOCKET
            _ => vec![0.0, 0.0, 1.0],  // EXTERNAL_IP
        };

        let mprotect_freq = self.mprotect_count / window_secs.max(1.0);

        let iat_variance = if self.packet_iat_count > 1 {
            let mean = self.packet_iat_sum / self.packet_iat_count as f64;
            let var  = self.packet_iat_sqsum / self.packet_iat_count as f64 - mean * mean;
            (var.max(0.0).sqrt() / 1e6) as f32  // convert ns to ms
        } else {
            0.0
        };

        let port_delta = self.unique_ports.len() as f32 / 65535.0;
        let event_freq = self.event_count / window_secs.max(1.0);

        vec![
            type_oh[0], type_oh[1], type_oh[2],
            mprotect_freq.min(100.0) / 100.0,  // normalised [0,1]
            iat_variance.min(1.0),
            port_delta,
            event_freq.min(10000.0) / 10000.0,
        ]
    }
}

#[derive(Debug, Default, Clone)]
struct EdgeState {
    weight:       f32,
    last_seen_ns: u64,
}

pub struct SlidingWindowGraph {
    events:           VecDeque<(u64, RadmEvent)>,
    window_ns:        u64,
    nodes:            HashMap<u64, (u32, NodeState)>,  // node_id → (index, state)
    next_node_idx:    u32,
    edges:            HashMap<(u32, u32), EdgeState>,  // (src_idx, dst_idx) → state
    cgroup_to_name:   HashMap<u64, String>,             // populated by cgroup resolver
}

impl SlidingWindowGraph {
    pub fn new(window_ms: u64) -> Self {
        Self {
            events:           VecDeque::new(),
            window_ns:        window_ms * 1_000_000,
            nodes:            HashMap::new(),
            next_node_idx:    0,
            edges:            HashMap::new(),
            cgroup_to_name:   HashMap::new(),
        }
    }

    pub fn ingest(&mut self, event: RadmEvent) {
        let ts = event.timestamp_ns;
        self.evict_expired(ts);
        self.update_from_event(&event);
        self.events.push_back((ts, event));
    }

    fn evict_expired(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(self.window_ns);
        // Remove events older than the window
        while let Some(&(ts, _)) = self.events.front() {
            if ts < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
        // Recompute node states from scratch when eviction occurs
        // (cheaper than maintaining reverse index for production scale ≤ 500 containers)
        self.recompute_state();
    }

    pub fn recompute_state(&mut self) {
        self.nodes.clear();
        self.next_node_idx = 0;
        self.edges.clear();

        // Re-ingest all active events in the window
        // We clone to avoid borrow checker issues during iteration
        let events_clone: Vec<RadmEvent> = self.events.iter().map(|&(_, ref ev)| ev.clone()).collect();
        for ev in &events_clone {
            self.update_from_event_inner(ev);
        }
    }

    fn update_from_event(&mut self, ev: &RadmEvent) {
        self.update_from_event_inner(ev);
    }

    fn update_from_event_inner(&mut self, ev: &RadmEvent) {
        // Ensure container node exists
        let c_idx = self.get_or_create_node(ev.cgroup_id, 0 /*CONTAINER*/, || {
            self.cgroup_to_name.get(&ev.cgroup_id)
                .cloned()
                .unwrap_or_else(|| format!("cg:{:x}", ev.cgroup_id))
        });

        // Update container node state
        if let Some((_, state)) = self.nodes.get_mut(&ev.cgroup_id) {
            state.event_count += 1.0;
            if ev.syscall_id == 1 { // RADM_SYS_MPROTECT
                state.mprotect_count += 1.0;
            }
        }

        // For network events: create destination node and edge
        if ev.event_type == 2 /*RADM_EVT_NETWORK*/ && ev.dst_ip != 0 {
            let dst_key = ev.dst_ip as u64;
            let d_idx = self.get_or_create_node(dst_key, 2 /*EXTERNAL_IP*/, || {
                format!("{}.{}.{}.{}",
                    ev.dst_ip & 0xFF,
                    (ev.dst_ip >> 8) & 0xFF,
                    (ev.dst_ip >> 16) & 0xFF,
                    (ev.dst_ip >> 24) & 0xFF)
            });

            if let Some((_, state)) = self.nodes.get_mut(&dst_key) {
                if ev.dst_port != 0 {
                    state.unique_ports.insert(ev.dst_port);
                }
                let ts = ev.timestamp_ns;
                if state.last_packet_ns != 0 {
                    let iat = (ts - state.last_packet_ns) as f64;
                    state.packet_iat_sum   += iat;
                    state.packet_iat_sqsum += iat * iat;
                    state.packet_iat_count += 1;
                }
                state.last_packet_ns = ts;
            }

            // Directed edge: container → external IP
            let edge = self.edges.entry((c_idx, d_idx)).or_default();
            edge.weight += 1.0;
            edge.last_seen_ns = ev.timestamp_ns;
        }
    }

    fn get_or_create_node(&mut self, id: u64, ntype: u32, label_fn: impl FnOnce() -> String) -> u32 {
        if let Some((idx, _)) = self.nodes.get(&id) {
            return *idx;
        }
        let idx = self.next_node_idx;
        self.next_node_idx += 1;
        let state = NodeState {
            node_id:   id,
            node_type: ntype,
            label:     label_fn(),
            ..Default::default()
        };
        self.nodes.insert(id, (idx, state));
        idx
    }

    pub fn to_snapshot(&self, seq: u64, window_start_ns: u64, window_end_ns: u64) -> GraphSnapshot {
        let window_secs = self.window_ns as f32 / 1e9;

        let nodes: Vec<NodeFeatures> = self.nodes.values().map(|(idx, state)| {
            NodeFeatures {
                node_index: *idx,
                node_id:    state.node_id,
                node_type:  state.node_type as i32,
                features:   state.to_features(window_secs),
                label:      state.label.clone(),
            }
        }).collect();

        let edges: Vec<ProtoEdge> = self.edges.iter().map(|((src, dst), state)| {
            ProtoEdge {
                src_index:    *src,
                dst_index:    *dst,
                weight:       state.weight,
                last_seen_ns: state.last_seen_ns,
            }
        }).collect();

        GraphSnapshot {
            window_start_ns,
            window_end_ns,
            sequence_id: seq,
            nodes,
            edges,
        }
    }
}

/// Drives the sliding-window graph and emits snapshots every `emit_interval_ms` ms.
pub async fn run_graph_builder(
    mut rx: mpsc::Receiver<RadmEvent>,
    snapshot_tx: mpsc::Sender<GraphSnapshot>,
    window_ms: u64,
    emit_interval_ms: u64,
) -> anyhow::Result<()> {
    let mut graph = SlidingWindowGraph::new(window_ms);
    let mut ticker = interval(Duration::from_millis(emit_interval_ms));
    let mut seq: u64 = 0;
    let mut window_start = 0u64;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if window_start == 0 { window_start = event.timestamp_ns; }
                graph.ingest(event);
            }
            _ = ticker.tick() => {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                let snap = graph.to_snapshot(seq, window_start, now_ns);
                seq += 1;
                window_start = now_ns;
                if snapshot_tx.send(snap).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

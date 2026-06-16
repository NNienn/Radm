// aggregator/src/config.rs
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AggregatorConfig {
    pub bpf_object_path:      String,   // path to compiled radm_tp.o / radm_tc.o / radm_xdp.o
    pub graph_socket_path:    String,   // UDS path to stream GraphSnapshot
    pub alert_socket_path:    String,   // UDS path to receive AnomalyAlert
    pub quarantine_map_pin:   String,   // /sys/fs/bpf/radm/quarantine_map
    pub pid_cgmap_pin:        String,   // /sys/fs/bpf/radm/pid_cgmap
    pub window_duration_ms:   u64,      // sliding window size (default: 5000)
    pub max_nodes:            usize,    // maximum graph nodes (default: 256)
    pub ringbuf_poll_timeout: u64,      // ring buffer poll timeout µs (default: 100)
    pub host_interface:       String,   // host NIC for XDP (e.g. eth0)
    pub container_runtime:    String,   // "docker" | "containerd"
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            bpf_object_path:      "/etc/radm/bpf".into(),
            graph_socket_path:    "/run/radm/graph.sock".into(),
            alert_socket_path:    "/run/radm/alert.sock".into(),
            quarantine_map_pin:   "/sys/fs/bpf/radm/quarantine_map".into(),
            pid_cgmap_pin:        "/sys/fs/bpf/radm/pid_cgmap".into(),
            window_duration_ms:   5_000,
            max_nodes:            256,
            ringbuf_poll_timeout: 100,
            host_interface:       "eth0".into(),
            container_runtime:    "containerd".into(),
        }
    }
}

pub fn load_config(path: &str) -> Result<AggregatorConfig, config::ConfigError> {
    let s = config::Config::builder()
        .add_source(config::File::with_name(path).required(false))
        .add_source(config::Environment::with_prefix("RADM"))
        .build()?;
    s.try_deserialize()
}

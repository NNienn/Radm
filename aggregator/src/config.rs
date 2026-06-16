use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AggregatorConfig {
    pub bpf_object_path: String,
    pub graph_socket_path: String,
    pub alert_socket_path: String,
    pub quarantine_map_pin: String,
    pub pid_cgmap_pin: String,
    pub window_duration_ms: u64,
    pub snapshot_interval_ms: u64,
    pub max_nodes: usize,
    pub ringbuf_poll_timeout: u64,
    pub host_interface: String,
    pub container_runtime: String,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            bpf_object_path: "/etc/radm/bpf".into(),
            graph_socket_path: "/run/radm/graph.sock".into(),
            alert_socket_path: "/run/radm/alert.sock".into(),
            quarantine_map_pin: "/sys/fs/bpf/radm/quarantine_map".into(),
            pid_cgmap_pin: "/sys/fs/bpf/radm/pid_cgmap".into(),
            window_duration_ms: 5_000,
            snapshot_interval_ms: 1_000,
            max_nodes: 256,
            ringbuf_poll_timeout: 100,
            host_interface: "eth0".into(),
            container_runtime: "containerd".into(),
        }
    }
}

pub fn load_config(path: &str) -> Result<AggregatorConfig, config::ConfigError> {
    let config = config::Config::builder()
        .add_source(config::File::with_name(path).required(false))
        .add_source(config::Environment::with_prefix("RADM"))
        .build()?;
    config.try_deserialize()
}

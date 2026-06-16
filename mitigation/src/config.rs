// mitigation/src/config.rs
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct MitigationConfig {
    pub alert_socket_path: String,
    pub forensic_dir:      String,
    pub bpf_pin_dir:       String,
    pub tc_bpf_obj:        String,
    pub auto_quarantine:   bool,
    pub dry_run:           bool,
}

impl Default for MitigationConfig {
    fn default() -> Self {
        Self {
            alert_socket_path: "/run/radm/alert.sock".into(),
            forensic_dir:      "/var/radm/forensics".into(),
            bpf_pin_dir:       "/sys/fs/bpf/radm".into(),
            tc_bpf_obj:        "/etc/radm/bpf/radm_tc.o".into(),
            auto_quarantine:   true,
            dry_run:           false,
        }
    }
}

pub fn load_config(path: &str) -> Result<MitigationConfig, config::ConfigError> {
    let s = config::Config::builder()
        .add_source(config::File::with_name(path).required(false))
        .add_source(config::Environment::with_prefix("RADM"))
        .build()?;
    s.try_deserialize()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NodeType {
    Container = 0,
    Socket = 1,
    ExternalIp = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeFeatures {
    #[prost(uint32, tag = "1")]
    pub node_index: u32,
    #[prost(uint64, tag = "2")]
    pub node_id: u64,
    #[prost(enumeration = "NodeType", tag = "3")]
    pub node_type: i32,
    #[prost(float, repeated, tag = "4")]
    pub features: ::prost::alloc::vec::Vec<f32>,
    #[prost(string, tag = "5")]
    pub label: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Edge {
    #[prost(uint32, tag = "1")]
    pub src_index: u32,
    #[prost(uint32, tag = "2")]
    pub dst_index: u32,
    #[prost(float, tag = "3")]
    pub weight: f32,
    #[prost(uint64, tag = "4")]
    pub last_seen_ns: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GraphSnapshot {
    #[prost(uint64, tag = "1")]
    pub window_start_ns: u64,
    #[prost(uint64, tag = "2")]
    pub window_end_ns: u64,
    #[prost(uint64, tag = "3")]
    pub sequence_id: u64,
    #[prost(message, repeated, tag = "4")]
    pub nodes: ::prost::alloc::vec::Vec<NodeFeatures>,
    #[prost(message, repeated, tag = "5")]
    pub edges: ::prost::alloc::vec::Vec<Edge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ThreatClass {
    Unknown = 0,
    LateralMovement = 1,
    MemoryInjection = 2,
    DataExfiltration = 3,
    PrivilegeEscalation = 4,
    FilelessExec = 5,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AnomalyAlert {
    #[prost(uint64, tag = "1")]
    pub alert_id: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_ns: u64,
    #[prost(uint64, tag = "3")]
    pub cgroup_id: u64,
    #[prost(uint32, tag = "4")]
    pub target_pid: u32,
    #[prost(string, tag = "5")]
    pub container_id: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub container_name: ::prost::alloc::string::String,
    #[prost(float, tag = "7")]
    pub anomaly_score: f32,
    #[prost(float, repeated, tag = "8")]
    pub node_errors: ::prost::alloc::vec::Vec<f32>,
    #[prost(enumeration = "ThreatClass", tag = "9")]
    pub threat_class: i32,
    #[prost(bytes, tag = "10")]
    pub raw_graph_snapshot: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum QuarantineStatus {
    Pending = 0,
    Active = 1,
    Failed = 2,
    Released = 3,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuarantineEvent {
    #[prost(uint64, tag = "1")]
    pub alert_id: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_ns: u64,
    #[prost(string, tag = "3")]
    pub container_id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "4")]
    pub target_pid: u32,
    #[prost(enumeration = "QuarantineStatus", tag = "5")]
    pub status: i32,
    #[prost(string, tag = "6")]
    pub veth_iface: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub forensic_path: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub error_msg: ::prost::alloc::string::String,
}

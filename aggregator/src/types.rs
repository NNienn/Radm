/* types.rs — Rust equivalents of structs defined in radm_types.h */

#[repr(C, align(8))]
#[derive(Debug, Copy, Clone, Default)]
pub struct RadmEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub syscall_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub memory_flags: u32,
    pub payload_hash: u32,
    pub event_type: u8,
    pub ip_proto: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct RadmRatelimitState {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

// Verify that the size in Rust matches the size in C (48 bytes)
const _: () = {
    if std::mem::size_of::<RadmEvent>() != 48 {
        panic!("Size of RadmEvent must be exactly 48 bytes");
    }
};

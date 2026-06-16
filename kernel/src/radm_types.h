/* radm_types.h — MUST be included by both C BPF programs and Rust bindgen */
#pragma once
#include <linux/types.h>

/* ── Event type discriminant ──────────────────────────────────────────── */
#define RADM_EVT_SYSCALL   0x01
#define RADM_EVT_NETWORK   0x02

/* ── Syscall IDs tracked ──────────────────────────────────────────────── */
#define RADM_SYS_MPROTECT  0x01
#define RADM_SYS_MMAP      0x02
#define RADM_SYS_PTRACE    0x03
#define RADM_SYS_MEMFD     0x04

/* ── Ring buffer entry  (48-byte aligned) ─────────────────── */
struct radm_event {
    __u64 timestamp_ns;     /* bpf_ktime_get_ns()                        */
    __u64 cgroup_id;        /* bpf_get_current_cgroup_id()               */
    __u32 pid;              /* lower 32 bits of bpf_get_current_pid_tgid */
    __u32 tgid;             /* upper 32 bits                             */
    __u32 syscall_id;       /* RADM_SYS_* or 0 for network events        */
    __u32 src_ip;           /* network-byte-order IPv4 (0 for syscalls)  */
    __u32 dst_ip;
    __u16 src_port;         /* host-byte-order                           */
    __u16 dst_port;
    __u32 memory_flags;     /* PROT_* flags for mprotect/mmap            */
    __u32 payload_hash;     /* murmur3 of first 32 payload bytes         */
    __u8  event_type;       /* RADM_EVT_SYSCALL | RADM_EVT_NETWORK       */
    __u8  ip_proto;         /* IPPROTO_TCP / IPPROTO_UDP                 */
    __u8  _pad[2];          /* explicit padding to align to 8-byte boundary */
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct radm_event) == 48, "radm_event size mismatch");

/* ── Token-bucket state (per-CPU rate limiter) ───────────────────────── */
struct radm_ratelimit_state {
    __u64 tokens;           /* current token count                       */
    __u64 last_refill_ns;   /* timestamp of last refill                  */
};

#define RADM_RATELIMIT_CAPACITY   10000   /* max tokens                  */
#define RADM_RATELIMIT_REFILL     1000    /* tokens per millisecond      */

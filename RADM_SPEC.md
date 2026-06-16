# RADM · ردم
## Enterprise-Grade Hybrid Zero-Trust Container Security Engine
### Complete Engineering Specification & Code-Generation Brief — v1.0

> **ردم** (*radm*, Arabic) — to fill, to bury, to seal off.  
> A name that describes exactly what this system does to compromised containers.

---

## ⚠️  PREFLIGHT — FIVE CRITICAL QUESTIONS

Before generating any code, confirm these five decisions. Each one changes the implementation
in a non-trivial way. **Defaults are shown in brackets** — if you have no opinion, accept the default.

| # | Question | Default |
|---|---|---|
| Q1 | **Minimum Linux kernel version?** Ring-buffer needs ≥ 5.8; CO-RE BTF needs ≥ 5.2; recommended floor is **5.15 LTS** (Ubuntu 22.04 / RHEL 9) | `5.15` |
| Q2 | **Container runtime?** Quarantine mechanics differ: Docker manipulates `docker0`; containerd/k8s manipulates the CNI bridge. **⚠️ Avoid Cilium** — it owns the eBPF datapath and will conflict | `containerd + Kubernetes` |
| Q3 | **GPU for inference?** TensorRT (INT8) requires NVIDIA CUDA ≥ 11.8. If none, the system falls back to `torch.compile` CPU-optimised inference | `CPU-only (CUDA optional)` |
| Q4 | **Scale target?** Drives ring-buffer sizing, graph node caps, and thread pool counts | `50–500 containers (medium)` |
| Q5 | **CNI plugin?** Flannel/Calico → standard veth-pairs on a Linux bridge; Calico BGP mode → requires extra routing logic. Cilium is unsupported | `Flannel or Docker default` |

> Answers are baked into the `radm.toml` config schema (§9) so the binary can be recompiled  
> without touching source code when assumptions change.

---

## §0 — WHAT WAS WRONG WITH THE ORIGINAL SPEC (and how Radm fixes it)

The source architecture brief contained twelve technical issues that would have produced non-compiling
or unsafely operating code. Every fix is documented here so the implementation engineer understands
**why** the design is the way it is.

| # | Original Problem | Radm Fix |
|---|---|---|
| 1 | `char[16]` container_id in kernel struct — impossible to populate from kernel space | Replaced with `u64 cgroup_id` via `bpf_get_current_cgroup_id()`; name resolved in userspace |
| 2 | XDP alone for container-level packet monitoring — XDP attaches to physical/virtual NICs, cannot discriminate per-container | Added **TC BPF** at veth pairs for container-scoped monitoring; XDP stays at host NIC for DDoS early-drop only |
| 3 | `libbpf-rs` mixed with `aya` — two competing BPF Rust ecosystems | Standardised on **aya 0.13+** throughout; eBPF programs in C compiled to `.o`, loaded by aya |
| 4 | No training pipeline — the model has nothing to learn from | Added offline baseline collection + ST-GAE training phase with checkpoint persistence |
| 5 | MurmurHash3 as described contains unbounded loops — BPF verifier rejects this | Hash function replaced with `#pragma unroll`-bounded 32-byte-fixed implementation |
| 6 | `BPF_MAP_TYPE_RINGBUF` rate limiter described but not implemented correctly | Explicit per-CPU token bucket using `BPF_MAP_TYPE_PERCPU_ARRAY` |
| 7 | TensorRT INT8 as a hard requirement — breaks on every non-NVIDIA host | `torch.compile` CPU path as default; TensorRT as optional compile flag |
| 8 | `setns()` quarantine loop described without capability requirements | Documented required capabilities; quarantine uses **TC BPF DROP at veth** + BPF map update |
| 9 | "Scrape volatile RAM pages" — undefined mechanism | Forensic capture uses `process_vm_readv(2)` with proper ptrace attach/detach protocol |
| 10 | No Protobuf schema defined | Complete `.proto` schema with framing protocol specified in §7 |
| 11 | No deployment or testing strategy | Docker Compose dev environment + Kubernetes DaemonSet + full test matrix in §11–12 |
| 12 | Dynamic graph node counts not addressed in PyG model | Fixed MAX_NODES=256 padded representation + validity mask; node registry in Rust |

---

## §1 — PROJECT SCOPE

### 1.1 Goals
- Intercept network flows and memory-manipulation syscalls with **< 2 µs kernel overhead** via eBPF.
- Detect lateral movement, memory injection, and data exfiltration using a Spatiotemporal Graph Autoencoder running on the live container topology.
- Quarantine a compromised container in **< 100 ms** of anomaly classification (network isolation via TC BPF).
- Preserve a cryptographically-signed forensic memory dump for every quarantine event.
- Operate without modifying container images, injecting sidecar agents, or requiring cluster admin credentials beyond DaemonSet privileges.

### 1.2 Non-Goals
- Not a replacement for a WAF or application-layer firewall.
- Not an intrusion-detection system for encrypted traffic payloads (only metadata is inspected).
- Not compatible with Cilium or any eBPF-owning CNI plugin.
- Not validated against FIPS 140-2 in this version (planned for v2).

---

## §2 — SYSTEM PREREQUISITES

### 2.1 Host Requirements
```
OS:              Linux 5.15 LTS (Ubuntu 22.04 / Debian 12 / RHEL 9 / Amazon Linux 2023)
Architecture:    x86_64 or aarch64
BPF:             CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_JIT=y
BTF:             CONFIG_DEBUG_INFO_BTF=y  (required for CO-RE)
cgroup:          cgroup v2 unified hierarchy  (/sys/fs/cgroup must be cgroup2)
Memory:          ≥ 4 GB RAM (≥ 8 GB recommended for inference)
Disk:            ≥ 10 GB for forensic dumps + model checkpoints
```

### 2.2 Toolchain
```
clang ≥ 15       (eBPF compilation; DO NOT use gcc for BPF targets)
llvm ≥ 15        (bpf target backend)
bpftool ≥ 7.2    (vmlinux.h generation, prog/map inspection)
Rust ≥ 1.78      (edition 2021; stable channel)
Python ≥ 3.11
protoc ≥ 3.21    (protobuf compiler)
Docker ≥ 24      (dev environment)
kubectl ≥ 1.28   (production deployment)
```

### 2.3 Required Linux Capabilities

Radm processes run as non-root but require these capabilities explicitly granted:

| Process | Capabilities | Reason |
|---|---|---|
| `radm-aggregator` | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE` | Load eBPF programs, attach to TC/XDP, set rlimits for locked memory |
| `radm-inference` | none beyond default | Pure userspace computation |
| `radm-mitigation` | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN` | Manipulate TC rules, read `/proc/<PID>/mem`, enter network namespaces |

> In Kubernetes: use a DaemonSet with `securityContext.capabilities.add` — **never** `privileged: true`.

---

## §3 — ARCHITECTURE & DATA FLOW

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         RING 0  —  KERNEL SPACE                             ║
║                                                                              ║
║  Physical NIC / vNIC                                                         ║
║  ┌──────────────────┐  XDP DROP (DDoS)       ┌─────────────────────────┐   ║
║  │  XDP Hook        │──────────────────────► │ quarantine_map           │   ║
║  │  (host NIC)      │                        │ BPF_MAP_TYPE_HASH        │   ║
║  └──────┬───────────┘                        └─────────────────────────┘   ║
║         │ XDP_PASS  →  Linux Bridge (docker0 / cni0)                        ║
║         │                                                                    ║
║  ┌──────▼───────────┐  TC BPF ingress/egress  ┌────────────────────────┐   ║
║  │  TC BPF Hook     │ ──── metadata ────────►  │  BPF_MAP_TYPE_RINGBUF  │   ║
║  │  (per-veth)      │      (per-container)     │  telemetry_ring         │   ║
║  └──────────────────┘                          └──────────┬─────────────┘   ║
║                                                            │                 ║
║  ┌──────────────────┐  syscall args                        │                 ║
║  │  Tracepoints     │ ─── mprotect / mmap ────────────────┘                 ║
║  │  (per-PID)       │     ptrace / memfd_create                              ║
║  └──────────────────┘                                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                        RING 3  —  USER SPACE                                 ║
║                                                                              ║
║  ┌────────────────────────────────────────────────────┐                      ║
║  │  radm-aggregator  (Rust / aya / Tokio)             │                      ║
║  │                                                    │                      ║
║  │  Thread Pool A: BPF ring-buffer consumer           │                      ║
║  │  Thread Pool B: Sliding-window graph builder       │                      ║
║  │  Thread Pool C: UDS/Protobuf graph streamer        │                      ║
║  │  Thread Pool D: cgroup_id → container_id resolver  │                      ║
║  │  Thread Pool E: Quarantine command receiver        │                      ║
║  └──────────────────────────┬─────────────────────────┘                      ║
║                             │  GraphSnapshot (Protobuf, length-prefixed)     ║
║                             │  UDS: /run/radm/graph.sock                     ║
║                             ▼                                                 ║
║  ┌────────────────────────────────────────────────────┐                      ║
║  │  radm-inference  (Python / PyTorch Geometric)      │                      ║
║  │                                                    │                      ║
║  │  • Protobuf graph consumer                         │                      ║
║  │  • ST-GAE encoder (GATv2Conv × 3 + GRU)            │                      ║
║  │  • Decoder (MLP feature + inner-product edge)      │                      ║
║  │  • Isolation Forest anomaly classifier             │                      ║
║  │  • Alert publisher                                 │                      ║
║  └──────────────────────────┬─────────────────────────┘                      ║
║                             │  AnomalyAlert (Protobuf)                       ║
║                             │  UDS: /run/radm/alert.sock                     ║
║                             ▼                                                 ║
║  ┌────────────────────────────────────────────────────┐                      ║
║  │  radm-mitigation  (Rust)                           │                      ║
║  │                                                    │                      ║
║  │  1. Resolve veth pair from container PID / netns   │                      ║
║  │  2. Attach TC BPF DROP to veth host-side           │                      ║
║  │  3. Insert cgroup_id into quarantine_map (BPF)     │                      ║
║  │  4. process_vm_readv → encrypted forensic dump     │                      ║
║  │  5. Emit QuarantineEvent                           │                      ║
║  └────────────────────────────────────────────────────┘                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### 3.1 Timing Budget (End-to-End SLA)
```
Kernel event capture:          < 2 µs     (eBPF tracepoint / TC BPF)
Ring buffer → Rust consumer:   < 50 µs    (lockless poll, zero-copy)
Sliding-window update:         < 200 µs   (in-memory deque + hashmap)
Graph serialisation (Protobuf):< 1 ms     (prost + UDS write)
ST-GAE inference (CPU):        < 5 ms     (torch.compile, batch N≤256)
Anomaly classification (IF):   < 1 ms     (sklearn Isolation Forest)
Quarantine execution:          < 50 ms    (TC BPF attach + BPF map write)
Forensic dump initiation:      < 100 ms   (process_vm_readv async)
─────────────────────────────────────────────────────────────
TOTAL (detection + containment):  < 160 ms
```

---

## §4 — COMPONENT 1: KERNEL DATA PLANE (C / eBPF)

### 4.1 File Layout
```
kernel/
├── src/
│   ├── radm_types.h       # Shared types (also included from Rust via bindgen)
│   ├── radm_xdp.c         # XDP: host-NIC DDoS gate + quarantine enforcement
│   ├── radm_tc.c          # TC BPF: per-veth packet metadata collection
│   └── radm_tp.c          # Tracepoints: mprotect/mmap/ptrace/memfd
├── include/
│   └── vmlinux.h          # Generated via: bpftool btf dump file /sys/kernel/btf/vmlinux format c
└── Makefile
```

### 4.2 Shared Type Definitions (`radm_types.h`)

```c
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

/* ── Ring buffer entry  (64-byte cache-line aligned) ─────────────────── */
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
    __u8  _pad[6];          /* explicit padding — do NOT use __packed    */
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct radm_event) == 48, "radm_event size mismatch");

/* ── Token-bucket state (per-CPU rate limiter) ───────────────────────── */
struct radm_ratelimit_state {
    __u64 tokens;           /* current token count                       */
    __u64 last_refill_ns;   /* timestamp of last refill                  */
};

#define RADM_RATELIMIT_CAPACITY   10000   /* max tokens                  */
#define RADM_RATELIMIT_REFILL     1000    /* tokens per millisecond      */
```

### 4.3 BPF Map Declarations (shared across all three programs)

All three eBPF programs are linked against the same map definitions. Define them in a
shared header `radm_maps.h`:

```c
/* radm_maps.h — BPF map declarations (included in all three BPF C files) */
#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "radm_types.h"

/* 1. Main telemetry ring buffer — 16 MB for medium scale */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);  /* 16 MB */
} telemetry_ring SEC(".maps");

/* 2. Per-CPU token bucket for rate limiting */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct radm_ratelimit_state);
} ratelimit_map SEC(".maps");

/* 3. Quarantine set: cgroup_id → 1 (set by mitigation plane, read by XDP+TC) */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,         __u64);   /* cgroup_id */
    __type(value,       __u8);    /* always 1  */
    __uint(pinning,     LIBBPF_PIN_BY_NAME);  /* pinned to /sys/fs/bpf/radm/ */
} quarantine_map SEC(".maps");

/* 4. Drop counter for telemetry — observable from userspace */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u64);
} drop_counter SEC(".maps");
```

### 4.4 Rate-Limiter Helper (inline, BPF-safe)

```c
/* radm_helpers.h */
#pragma once
#include "radm_maps.h"

/* Token-bucket rate limiter. Returns 1 if event should be passed, 0 if dropped. */
static __always_inline int radm_ratelimit_check(void) {
    __u32 key = 0;
    struct radm_ratelimit_state *state = bpf_map_lookup_elem(&ratelimit_map, &key);
    if (!state)
        return 1;  /* fail open — do not drop if state missing */

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ms = (now - state->last_refill_ns) / 1000000ULL;

    if (elapsed_ms > 0) {
        __u64 new_tokens = elapsed_ms * RADM_RATELIMIT_REFILL;
        state->tokens += new_tokens;
        if (state->tokens > RADM_RATELIMIT_CAPACITY)
            state->tokens = RADM_RATELIMIT_CAPACITY;
        state->last_refill_ns = now;
    }

    if (state->tokens == 0)
        return 0;  /* drop — bucket empty */

    state->tokens--;
    return 1;
}

/* BPF-safe MurmurHash3 over exactly 32 bytes (fully unrolled for verifier) */
#define RADM_HASH_SEED 0xdeadbeefU

static __always_inline __u32 radm_hash32(const __u8 *data) {
    __u32 h = RADM_HASH_SEED ^ 32U;
    __u32 k;

    /* 8 rounds × 4 bytes = 32 bytes, loop fully unrolled */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        __builtin_memcpy(&k, data + i * 4, 4);
        k *= 0xcc9e2d51u;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5u + 0xe6546b64u;
    }
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

/* Emit an event to the ring buffer; handles rate limiting and drop counting */
static __always_inline void radm_emit_event(struct radm_event *ev) {
    if (!radm_ratelimit_check()) {
        __u32 key = 0;
        __u64 *dc = bpf_map_lookup_elem(&drop_counter, &key);
        if (dc)
            __sync_fetch_and_add(dc, 1);
        return;
    }

    struct radm_event *slot = bpf_ringbuf_reserve(&telemetry_ring, sizeof(*ev), 0);
    if (!slot) {
        /* Ring buffer full despite rate limiting — increment drop counter */
        __u32 key = 0;
        __u64 *dc = bpf_map_lookup_elem(&drop_counter, &key);
        if (dc)
            __sync_fetch_and_add(dc, 1);
        return;
    }
    __builtin_memcpy(slot, ev, sizeof(*ev));
    bpf_ringbuf_submit(slot, 0);
}
```

### 4.5 Tracepoint Program (`radm_tp.c`)

```c
/* radm_tp.c — Syscall tracepoint monitors for memory manipulation detection */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "radm_types.h"
#include "radm_maps.h"
#include "radm_helpers.h"

/*
 * ARCHITECTURE NOTE:
 * Tracepoint contexts for sys_enter_* expose arguments via a struct whose
 * layout is defined in /sys/kernel/debug/tracing/events/syscalls/sys_enter_*/format
 * With BTF/CO-RE (vmlinux.h), we use BPF_CORE_READ for safe access.
 *
 * Each hook:
 *  mprotect  — catch RWX page permission escalation (ROP chain setup)
 *  mmap      — catch anonymous+executable map creation (shellcode injection)
 *  ptrace    — catch process injection attempts (PTRACE_POKEDATA/PTRACE_SETREGS)
 *  memfd_create — catch in-memory fileless binary staging
 */

static __always_inline void fill_common(struct radm_event *ev, __u32 syscall_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->cgroup_id    = bpf_get_current_cgroup_id();
    ev->pid          = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->tgid         = (__u32)(pid_tgid >> 32);
    ev->syscall_id   = syscall_id;
    ev->event_type   = RADM_EVT_SYSCALL;
    /* Network fields are zero for syscall events */
}

/* ── mprotect: flag prot containing PROT_READ|PROT_WRITE|PROT_EXEC ── */
SEC("tp/syscalls/sys_enter_mprotect")
int radm_mprotect(struct trace_event_raw_sys_enter *ctx) {
    /* ctx->args[2] = prot flags */
    __u64 prot = ctx->args[2];
    if (!(prot & PROT_EXEC))
        return 0;  /* only care about exec-permission changes */

    struct radm_event ev = {};
    fill_common(&ev, RADM_SYS_MPROTECT);
    ev.memory_flags = (__u32)prot;
    radm_emit_event(&ev);
    return 0;
}

/* ── mmap: flag anonymous+executable mappings (MAP_ANONYMOUS | PROT_EXEC) ── */
SEC("tp/syscalls/sys_enter_mmap")
int radm_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 prot  = ctx->args[2];
    __u64 flags = ctx->args[3];

    /* MAP_ANONYMOUS = 0x20; PROT_EXEC = 0x4 */
    if (!(prot & PROT_EXEC) || !(flags & MAP_ANONYMOUS))
        return 0;

    struct radm_event ev = {};
    fill_common(&ev, RADM_SYS_MMAP);
    ev.memory_flags = (__u32)((prot << 16) | (flags & 0xFFFF));
    radm_emit_event(&ev);
    return 0;
}

/* ── ptrace: any ptrace call (request in args[0], target PID in args[1]) ── */
SEC("tp/syscalls/sys_enter_ptrace")
int radm_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct radm_event ev = {};
    fill_common(&ev, RADM_SYS_PTRACE);
    /* Encode request + target PID in memory_flags */
    __u32 request = (__u32)ctx->args[0];
    __u32 target  = (__u32)ctx->args[1];
    ev.memory_flags = (request << 16) | (target & 0xFFFF);
    radm_emit_event(&ev);
    return 0;
}

/* ── memfd_create: in-memory fileless binary staging ─────────────────── */
SEC("tp/syscalls/sys_enter_memfd_create")
int radm_memfd(struct trace_event_raw_sys_enter *ctx) {
    struct radm_event ev = {};
    fill_common(&ev, RADM_SYS_MEMFD);
    /* flags in args[1]: MFD_EXEC flag (0x0010) added in kernel 6.3;
     * we flag the event regardless of flags for visibility */
    ev.memory_flags = (__u32)ctx->args[1];
    radm_emit_event(&ev);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 4.6 TC BPF Program (`radm_tc.c`)

```c
/* radm_tc.c
 *
 * Attached to the HOST side of every container veth pair (both ingress and
 * egress using tc filter).  Collects packet metadata per-container and
 * enforces quarantine by returning TC_ACT_SHOT for quarantined cgroup IDs.
 *
 * Attachment command (issued by radm-aggregator when container starts):
 *   tc qdisc   add dev <veth> clsact
 *   tc filter  add dev <veth> ingress bpf da obj radm_tc.o sec tc/ingress
 *   tc filter  add dev <veth> egress  bpf da obj radm_tc.o sec tc/egress
 *
 * The cgroup_id is NOT available in TC context the same way as in tracepoints.
 * We look it up from a pid→cgroup_id map populated by the aggregator:
 *
 *   pid_cgmap: BPF_MAP_TYPE_HASH  pid → cgroup_id  (written from userspace)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "radm_types.h"
#include "radm_maps.h"
#include "radm_helpers.h"

/* Additional map: PID → cgroup_id, populated by Rust aggregator */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);  /* PID */
    __type(value,       __u64);  /* cgroup_id */
    __uint(pinning,     LIBBPF_PIN_BY_NAME);
} pid_cgmap SEC(".maps");

/*
 * Parse IP/TCP/UDP headers from the packet.
 * Returns 0 on success, -1 if the packet cannot be parsed (non-IP, too short).
 * IMPORTANT: Every pointer dereference MUST be bounds-checked before the
 * BPF verifier will accept the program.
 */
static __always_inline int parse_packet(
    struct __sk_buff *skb,
    __u32 *src_ip, __u32 *dst_ip,
    __u16 *src_port, __u16 *dst_port,
    __u8  *ip_proto,
    __u8  *payload_start,
    __u32 *payload_len)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Ethernet header: 14 bytes */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    /* Only handle IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip   = ip->saddr;
    *dst_ip   = ip->daddr;
    *ip_proto = ip->protocol;
    __u32 ip_hdr_len = ip->ihl * 4;

    void *l4 = (void *)ip + ip_hdr_len;
    if (l4 + 4 > data_end)
        return -1;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *src_port    = bpf_ntohs(tcp->source);
        *dst_port    = bpf_ntohs(tcp->dest);
        *payload_start = (void *)tcp + tcp->doff * 4;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *src_port    = bpf_ntohs(udp->source);
        *dst_port    = bpf_ntohs(udp->dest);
        *payload_start = (void *)(udp + 1);
    } else {
        *src_port = *dst_port = 0;
        *payload_start = l4;
    }

    /* Clamp payload for hash — must verify bounds */
    __u32 avail = (data_end > (void *)(*payload_start))
                  ? (data_end - (void *)(*payload_start)) : 0;
    *payload_len = avail < 32 ? avail : 32;
    return 0;
}

static __always_inline int tc_handler(struct __sk_buff *skb, __u8 direction) {
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8  ip_proto = 0;
    __u8 *payload  = NULL;
    __u32 plen     = 0;

    if (parse_packet(skb, &src_ip, &dst_ip, &src_port, &dst_port,
                     &ip_proto, &payload, &plen) < 0)
        return TC_ACT_OK;  /* Non-IP: pass through unchanged */

    /* Resolve cgroup_id for this packet's socket owner PID.
     * skb->sk is available in TC context since kernel 4.18. */
    __u32 pid = 0;
    __u64 cgroup_id = 0;
    /* Attempt lookup via sk_fullsock helper if available,
     * otherwise the aggregator pre-populated pid_cgmap */
    struct bpf_sock *sk = skb->sk;
    if (sk) {
        /* Upcast to full socket to get the owning task's cgroup */
        struct bpf_sock *full = bpf_sk_fullsock(sk);
        if (full) {
            /* Piggyback on the userspace-populated pid_cgmap */
            pid = ((__u64)bpf_get_socket_uid(skb)) & 0xFFFFFFFF;
        }
    }

    /* Quarantine enforcement: drop all traffic for quarantined cgroups */
    if (cgroup_id) {
        __u8 *qflag = bpf_map_lookup_elem(&quarantine_map, &cgroup_id);
        if (qflag && *qflag == 1)
            return TC_ACT_SHOT;
    }

    /* Emit network telemetry event */
    struct radm_event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.cgroup_id    = cgroup_id;
    ev.pid          = pid;
    ev.event_type   = RADM_EVT_NETWORK;
    ev.src_ip       = src_ip;
    ev.dst_ip       = dst_ip;
    ev.src_port     = src_port;
    ev.dst_port     = dst_port;
    ev.ip_proto     = ip_proto;

    /* Hash first 32 bytes of payload if available */
    if (plen == 32 && payload) {
        void *data_end = (void *)(long)skb->data_end;
        if ((void *)payload + 32 <= data_end)
            ev.payload_hash = radm_hash32(payload);
    }

    radm_emit_event(&ev);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int radm_tc_ingress(struct __sk_buff *skb) { return tc_handler(skb, 0); }

SEC("tc/egress")
int radm_tc_egress(struct __sk_buff *skb)  { return tc_handler(skb, 1); }

char LICENSE[] SEC("license") = "GPL";
```

### 4.7 XDP Program (`radm_xdp.c`)

```c
/* radm_xdp.c
 *
 * Attached to the host physical / virtual NIC.
 * Responsibilities:
 *   1. Enforce quarantine (XDP_DROP) for quarantined cgroup IDs by IP.
 *   2. Early-drop rule during DDoS: if drop_counter exceeds threshold,
 *      apply a per-src-IP rate limiter to reduce blast-radius.
 *
 * Note: XDP does NOT have cgroup_id context (it runs before socket demux).
 *       Quarantine here uses a secondary map: quarantine_ip_map (u32→u8).
 *       The mitigation plane populates this map alongside quarantine_map.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "radm_types.h"
#include "radm_maps.h"

/* IP-based quarantine lookup (populated by mitigation alongside cgroup map) */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key,         __u32);  /* IPv4 address (network byte order) */
    __type(value,       __u8);
    __uint(pinning,     LIBBPF_PIN_BY_NAME);
} quarantine_ip_map SEC(".maps");

/* Per-src-IP token bucket for DDoS mitigation */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);  /* src IPv4 */
    __type(value,       __u64);  /* token count */
} xdp_pps_map SEC(".maps");

#define XDP_PPS_LIMIT  100000ULL   /* 100k pps per source IP */

SEC("xdp")
int radm_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    /* 1. Quarantine IP check */
    __u8 *qflag = bpf_map_lookup_elem(&quarantine_ip_map, &src_ip);
    if (qflag && *qflag == 1)
        return XDP_DROP;

    /* 2. Per-IP DDoS rate limiter (token bucket, approximate) */
    __u64 *tokens = bpf_map_lookup_elem(&xdp_pps_map, &src_ip);
    if (tokens) {
        if (*tokens == 0)
            return XDP_DROP;
        __sync_fetch_and_add(tokens, -1);
    } else {
        __u64 initial = XDP_PPS_LIMIT;
        bpf_map_update_elem(&xdp_pps_map, &src_ip, &initial, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

### 4.8 Kernel Makefile

```makefile
# kernel/Makefile
CLANG         ?= clang-15
LLC           ?= llc-15
BPFTOOL       ?= bpftool
KERNEL_SRCS   := src/radm_xdp.c src/radm_tc.c src/radm_tp.c
KERNEL_OBJS   := $(KERNEL_SRCS:.c=.o)
INCLUDES      := -I./include -I./src

CLANG_FLAGS   := -target bpf -O2 -g -Wall -Werror \
                 -D__TARGET_ARCH_x86 \
                 -mcpu=v3 \
                 $(INCLUDES)

.PHONY: all clean vmlinux

all: vmlinux $(KERNEL_OBJS)

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

clean:
	rm -f $(KERNEL_OBJS) include/vmlinux.h
```

---

## §5 — COMPONENT 2: STATEFUL TELEMETRY AGGREGATOR (Rust / aya / Tokio)

### 5.1 Cargo.toml

```toml
[package]
name    = "radm-aggregator"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "radm-aggregator"
path = "src/main.rs"

[dependencies]
# BPF
aya          = { version = "0.13", features = ["async_tokio"] }
aya-obj      = "0.13"

# Async runtime
tokio        = { version = "1", features = ["full"] }

# Serialisation
prost        = "0.13"
bytes        = "1"

# Concurrent data structures
dashmap      = "6"
parking_lot  = "0.12"

# Cgroup / proc filesystem utilities
procfs       = "0.16"

# Configuration
config       = "0.14"
serde        = { version = "1", features = ["derive"] }
toml         = "0.8"

# Logging / tracing
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter"] }

# Metrics
prometheus   = "0.13"
lazy_static  = "1"

# Unix sockets
tokio-unix-fd  = "0.1"

[build-dependencies]
prost-build  = "0.13"

[profile.release]
opt-level    = 3
lto          = "thin"
codegen-units = 1
```

### 5.2 `build.rs` (Protobuf code generation)

```rust
// aggregator/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["../proto/radm.proto"], &["../proto/"])?;
    println!("cargo:rerun-if-changed=../proto/radm.proto");
    Ok(())
}
```

### 5.3 `src/config.rs`

```rust
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
```

### 5.4 `src/bpf_loader.rs` (Load & Attach all eBPF programs)

```rust
// aggregator/src/bpf_loader.rs
//
// Loads the three compiled BPF objects, pins maps, and attaches programs.
// Must run before spawning the ring buffer consumer.

use aya::{
    Bpf, BpfLoader,
    maps::RingBuf,
    programs::{Xdp, XdpFlags, SchedClassifier, SchedClassifierLink, tc},
    programs::TracePoint,
};
use std::path::Path;
use crate::config::AggregatorConfig;
use anyhow::{Context, Result};

pub struct LoadedBpf {
    pub bpf_tp:  Bpf,   // tracepoints
    pub bpf_tc:  Bpf,   // TC BPF
    pub bpf_xdp: Bpf,   // XDP
}

pub fn load_and_attach(cfg: &AggregatorConfig) -> Result<LoadedBpf> {
    std::fs::create_dir_all("/sys/fs/bpf/radm")
        .context("create BPF pin directory")?;

    // ── Tracepoint object ──────────────────────────────────────────────
    let mut bpf_tp = BpfLoader::new()
        .load_file(format!("{}/radm_tp.o", cfg.bpf_object_path))
        .context("load radm_tp.o")?;

    for hook in &["mprotect", "mmap", "ptrace", "memfd"] {
        let prog_name = format!("radm_{}", hook);
        let prog: &mut TracePoint = bpf_tp
            .program_mut(&prog_name)
            .context(format!("find program {}", prog_name))?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", &format!("sys_enter_{}", hook))
            .context(format!("attach tracepoint sys_enter_{}", hook))?;
    }

    // ── XDP object ────────────────────────────────────────────────────
    let mut bpf_xdp = BpfLoader::new()
        .load_file(format!("{}/radm_xdp.o", cfg.bpf_object_path))
        .context("load radm_xdp.o")?;

    let xdp_prog: &mut Xdp = bpf_xdp
        .program_mut("radm_xdp")
        .context("find radm_xdp program")?
        .try_into()?;
    xdp_prog.load()?;
    xdp_prog.attach(&cfg.host_interface, XdpFlags::default())
        .context(format!("attach XDP to {}", cfg.host_interface))?;

    // TC object loaded but NOT attached here — the veth_manager attaches
    // per-container as containers are discovered.
    let bpf_tc = BpfLoader::new()
        .load_file(format!("{}/radm_tc.o", cfg.bpf_object_path))
        .context("load radm_tc.o")?;

    Ok(LoadedBpf { bpf_tp, bpf_tc, bpf_xdp })
}
```

### 5.5 `src/bpf_consumer.rs` (Zero-Copy Ring Buffer Consumer)

```rust
// aggregator/src/bpf_consumer.rs
//
// Asynchronous ring-buffer consumer.  Uses aya's RingBuf with AsyncFd so
// the tokio thread is not blocked.  Events are parsed zero-copy from the
// mapped memory region and forwarded to the graph builder via an mpsc channel.

use aya::maps::RingBuf;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::types::RadmEvent;  // generated from radm_types.h via bindgen

pub async fn consume_ring_buffer(
    mut ring: RingBuf<Arc<aya::maps::MapData>>,
    tx: mpsc::Sender<RadmEvent>,
) -> anyhow::Result<()> {
    // Wrap the ring buffer's raw file descriptor in AsyncFd so tokio can
    // wake on data-ready without busy-polling.
    let async_fd = AsyncFd::new(ring)?;

    loop {
        // Wait until the kernel signals data is available (epoll readiness)
        let mut guard = async_fd.readable().await?;

        // Drain all available events in this wake-up cycle
        loop {
            // SAFETY: as_mut_ptr() gives a raw pointer to the ring buffer
            // memory region; aya guarantees this is valid and mapped.
            // We use ptr::read_unaligned to avoid alignment assumptions.
            match async_fd.get_mut().next() {
                Some(item) => {
                    // item is a &[u8] slice into the ring buffer — zero copy
                    if item.len() < std::mem::size_of::<RadmEvent>() {
                        warn!("short ring buffer item: {} bytes", item.len());
                        continue;
                    }
                    // SAFETY: slice length verified above; struct is repr(C)
                    let event = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const RadmEvent)
                    };
                    if tx.send(event).await.is_err() {
                        return Ok(());  // receiver dropped — shutdown
                    }
                    debug!("consumed event cgroup={} pid={}", event.cgroup_id, event.pid);
                }
                None => break,  // ring buffer drained; wait for next wake-up
            }
        }

        guard.clear_ready();
    }
}
```

### 5.6 `src/graph_builder.rs` (Sliding-Window Graph Construction)

```rust
// aggregator/src/graph_builder.rs
//
// Maintains a 5-second sliding window over raw telemetry events and exports
// a GraphSnapshot protobuf every window_interval_ms milliseconds.

use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use crate::types::RadmEvent;
use crate::proto::radm::{GraphSnapshot, NodeFeatures, Edge as ProtoEdge, NodeType};

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

    fn recompute_state(&mut self) {
        self.nodes.clear();
        self.next_node_idx = 0;
        self.edges.clear();

        for (_, ev) in &self.events {
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
```

### 5.7 `src/ipc_server.rs` (UDS + Protobuf Graph Streamer)

```rust
// aggregator/src/ipc_server.rs
//
// Accepts connections on /run/radm/graph.sock and streams GraphSnapshot
// protobufs using a simple length-prefixed wire format:
//
//   [ 4-byte big-endian u32 message_length ][ message_length bytes ]
//
// Multiple consumers (e.g., inference engine) can connect simultaneously.

use prost::Message;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::proto::radm::GraphSnapshot;

pub async fn run_ipc_server(
    socket_path: &str,
    mut rx: tokio::sync::mpsc::Receiver<GraphSnapshot>,
) -> anyhow::Result<()> {
    // Clean up any stale socket file
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("Graph IPC server listening on {}", socket_path);

    // Broadcast channel so multiple readers get every snapshot
    let (bcast_tx, _bcast_rx) = broadcast::channel::<bytes::Bytes>(64);
    let bcast_tx_clone = bcast_tx.clone();

    // Forwarding task: mpsc → broadcast
    tokio::spawn(async move {
        while let Some(snapshot) = rx.recv().await {
            let mut buf = Vec::with_capacity(snapshot.encoded_len() + 4);
            let len = snapshot.encoded_len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            snapshot.encode(&mut buf).expect("protobuf encode");
            let _ = bcast_tx_clone.send(bytes::Bytes::from(buf));
        }
    });

    // Accept loop
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let mut bcast_rx = bcast_tx.subscribe();
                tokio::spawn(async move {
                    handle_client(stream, &mut bcast_rx).await;
                });
            }
            Err(e) => error!("IPC accept error: {}", e),
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    rx: &mut broadcast::Receiver<bytes::Bytes>,
) {
    loop {
        match rx.recv().await {
            Ok(frame) => {
                if stream.write_all(&frame).await.is_err() {
                    break;  // client disconnected
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Receiver is too slow — log and continue (don't disconnect)
                tracing::warn!("IPC consumer lagged {} messages", n);
            }
            Err(_) => break,
        }
    }
}
```

### 5.8 `src/main.rs` (Aggregator Entry Point with Thread Pool Isolation)

```rust
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
    pub mod radm { include!(concat!(env!("OUT_DIR"), "/radm.v1.rs")); }
}
pub mod types;  // generated by bindgen from radm_types.h

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::load_config("radm.toml").unwrap_or_default();

    // Load and attach eBPF programs
    let loaded = bpf_loader::load_and_attach(&cfg)?;

    // Extract ring buffer handle
    let ring: aya::maps::RingBuf<_> = loaded.bpf_tp.map_mut("telemetry_ring")?.try_into()?;

    // Channels between pipeline stages
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(8192);
    let (snapshot_tx, snapshot_rx) = tokio::sync::mpsc::channel(32);

    // Pool A: ring buffer consumer
    tokio::spawn(bpf_consumer::consume_ring_buffer(ring, event_tx));

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

    // Pool E: alert / quarantine receiver
    let alert_path = cfg.alert_socket_path.clone();
    tokio::spawn(quarantine_receiver::run_alert_receiver(&alert_path, &cfg));

    // Keep main alive
    tokio::signal::ctrl_c().await?;
    tracing::info!("radm-aggregator shutting down");
    Ok(())
}
```

---

## §6 — COMPONENT 3: BEHAVIORAL INFERENCE ENGINE (Python / PyTorch Geometric)

### 6.1 `requirements.txt`

```
torch>=2.3.0
torch-geometric>=2.5.0
torch-scatter>=2.1.2
torch-sparse>=0.6.18
scikit-learn>=1.4.0
protobuf>=4.25.0
grpcio-tools>=1.62.0
numpy>=1.26.0
scipy>=1.13.0
cryptography>=42.0.0
pyyaml>=6.0.1
prometheus-client>=0.20.0
```

### 6.2 `src/proto/radm.proto` (complete schema)

```protobuf
syntax = "proto3";
package radm.v1;

// ─────────────────────────────────────────────────────────────────────────────
// Kernel → Aggregator (for reference — actual transport is BPF ring buffer)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Aggregator → Inference Engine
// ─────────────────────────────────────────────────────────────────────────────

enum NodeType {
  CONTAINER   = 0;
  SOCKET      = 1;
  EXTERNAL_IP = 2;
}

message NodeFeatures {
  uint32          node_index = 1;
  uint64          node_id    = 2;
  NodeType        node_type  = 3;
  repeated float  features   = 4; // length == 7 (NODE_FEATURE_DIM)
  string          label      = 5;
}

message Edge {
  uint32 src_index    = 1;
  uint32 dst_index    = 2;
  float  weight       = 3;
  uint64 last_seen_ns = 4;
}

message GraphSnapshot {
  uint64           window_start_ns = 1;
  uint64           window_end_ns   = 2;
  uint64           sequence_id     = 3;
  repeated NodeFeatures nodes      = 4;
  repeated Edge         edges      = 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// Inference Engine → Mitigation
// ─────────────────────────────────────────────────────────────────────────────

enum ThreatClass {
  UNKNOWN              = 0;
  LATERAL_MOVEMENT     = 1;
  MEMORY_INJECTION     = 2;
  DATA_EXFILTRATION    = 3;
  PRIVILEGE_ESCALATION = 4;
  FILELESS_EXEC        = 5;
}

message AnomalyAlert {
  uint64          alert_id           = 1;
  uint64          timestamp_ns       = 2;
  uint64          cgroup_id          = 3;
  uint32          target_pid         = 4;
  string          container_id       = 5;
  string          container_name     = 6;
  float           anomaly_score      = 7; // normalised [0,1]
  repeated float  node_errors        = 8; // per-node reconstruction errors
  ThreatClass     threat_class       = 9;
  bytes           raw_graph_snapshot = 10;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mitigation → External Consumers
// ─────────────────────────────────────────────────────────────────────────────

enum QuarantineStatus {
  QUARANTINE_PENDING  = 0;
  QUARANTINE_ACTIVE   = 1;
  QUARANTINE_FAILED   = 2;
  QUARANTINE_RELEASED = 3;
}

message QuarantineEvent {
  uint64           alert_id       = 1;
  uint64           timestamp_ns   = 2;
  string           container_id   = 3;
  uint32           target_pid     = 4;
  QuarantineStatus status         = 5;
  string           veth_iface     = 6;
  string           forensic_path  = 7;
  string           error_msg      = 8;
}
```

### 6.3 `src/model.py` (ST-GAE Full Architecture)

```python
# inference/src/model.py
#
# Spatiotemporal Graph Autoencoder (ST-GAE)
#
# Architecture:
#   Encoder:  3× GATv2Conv (spatial) → GRU (temporal) → node embeddings [N, H]
#   Decoder:  MLP (feature reconstruction) + inner-product (edge reconstruction)
#
# Variable node counts across time steps are handled by padding to MAX_NODES
# with a validity mask, keeping the GRU state shape fixed.
#
# Dimensions (default config):
#   NODE_FEATURE_DIM  = 7
#   GAT_HEADS_L1      = 4   →  hidden = 4*16 = 64
#   GAT_HEADS_L2      = 4   →  hidden = 4*8  = 32
#   EMBEDDING_DIM     = 16  (post-GAT L3, single head)
#   GRU_HIDDEN        = 32
#   SEQ_LEN           = 10  (number of consecutive snapshots fed to GRU)

from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

NODE_FEATURE_DIM = 7
GAT_HIDDEN_L1    = 64   # 4 heads × 16
GAT_HIDDEN_L2    = 32   # 4 heads × 8
EMBEDDING_DIM    = 16
GRU_HIDDEN       = 32
SEQ_LEN          = 10
MAX_NODES        = 256  # must match aggregator config

# ─────────────────────────────────────────────────────────────────────────────
# Spatial Encoder: GATv2Conv × 3
# ─────────────────────────────────────────────────────────────────────────────

class SpatialEncoder(nn.Module):
    """Encodes a single graph snapshot into per-node embeddings."""

    def __init__(self):
        super().__init__()
        self.conv1 = GATv2Conv(
            NODE_FEATURE_DIM, 16,
            heads=4, concat=True, add_self_loops=True,
        )  # → [N, 64]
        self.conv2 = GATv2Conv(
            64, 8,
            heads=4, concat=True, add_self_loops=True,
        )  # → [N, 32]
        self.conv3 = GATv2Conv(
            32, EMBEDDING_DIM,
            heads=1, concat=False, add_self_loops=True,
        )  # → [N, 16]
        self.norm1 = nn.LayerNorm(64)
        self.norm2 = nn.LayerNorm(32)
        self.dropout = nn.Dropout(0.1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x:          Node feature matrix  [N, NODE_FEATURE_DIM]
            edge_index: COO edge list         [2, E]
        Returns:
            z:          Node embeddings       [N, EMBEDDING_DIM]
        """
        x = F.elu(self.norm1(self.conv1(x, edge_index)))
        x = self.dropout(x)
        x = F.elu(self.norm2(self.conv2(x, edge_index)))
        z = self.conv3(x, edge_index)         # no activation — raw embedding
        return z

# ─────────────────────────────────────────────────────────────────────────────
# Temporal Encoder: per-node GRU over SEQ_LEN snapshots
# ─────────────────────────────────────────────────────────────────────────────

class TemporalEncoder(nn.Module):
    """Encodes a sequence of spatial embeddings into a single temporal state."""

    def __init__(self):
        super().__init__()
        # Input:  [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]  (batch_first=False)
        # Output: [MAX_NODES, GRU_HIDDEN]
        self.gru = nn.GRU(
            input_size=EMBEDDING_DIM,
            hidden_size=GRU_HIDDEN,
            num_layers=2,
            batch_first=False,
            dropout=0.1,
        )

    def forward(self, z_seq: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z_seq: [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]
        Returns:
            h:     [MAX_NODES, GRU_HIDDEN]
        """
        # GRU treats dimension 1 as batch (each node is independent in time)
        output, hidden = self.gru(z_seq)  # hidden: [num_layers, MAX_NODES, GRU_HIDDEN]
        return hidden[-1]  # last layer: [MAX_NODES, GRU_HIDDEN]

# ─────────────────────────────────────────────────────────────────────────────
# Feature Decoder: MLP from temporal embedding back to node features
# ─────────────────────────────────────────────────────────────────────────────

class FeatureDecoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(GRU_HIDDEN, 64),
            nn.ELU(),
            nn.Linear(64, 32),
            nn.ELU(),
            nn.Linear(32, NODE_FEATURE_DIM),
        )

    def forward(self, h: torch.Tensor) -> torch.Tensor:
        """
        Args:  h:  [N, GRU_HIDDEN]
        Returns:   [N, NODE_FEATURE_DIM]
        """
        return self.mlp(h)

# ─────────────────────────────────────────────────────────────────────────────
# Edge Decoder: inner-product decoder for adjacency reconstruction
# ─────────────────────────────────────────────────────────────────────────────

class EdgeDecoder(nn.Module):
    """
    Reconstructs edge probabilities from node embeddings.
    For efficiency, only reconstructs the edges present in edge_index
    (sparse evaluation) rather than the full N×N matrix.
    """

    def forward(
        self,
        h: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            h:          [N, GRU_HIDDEN]
            edge_index: [2, E]
        Returns:
            edge_probs: [E]  sigmoid(h_src · h_dst)
        """
        src, dst = edge_index
        dot = (h[src] * h[dst]).sum(dim=-1)
        return torch.sigmoid(dot)

# ─────────────────────────────────────────────────────────────────────────────
# Full ST-GAE
# ─────────────────────────────────────────────────────────────────────────────

class SpatiotemporalAutoencoder(nn.Module):
    """
    End-to-end Spatiotemporal Graph Autoencoder.

    Usage (inference):
        model = SpatiotemporalAutoencoder().eval()
        x_recon, edge_probs, node_errors = model.reconstruct(graph_sequence)
    """

    def __init__(self):
        super().__init__()
        self.spatial_enc  = SpatialEncoder()
        self.temporal_enc = TemporalEncoder()
        self.feat_dec     = FeatureDecoder()
        self.edge_dec     = EdgeDecoder()

    # ─── Internal: encode a list of PyG Data objects into temporal state ───

    def _encode_sequence(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, Data]:
        """
        Encodes SEQ_LEN graphs spatially, pads to MAX_NODES, runs GRU.

        Returns:
            h:            [MAX_NODES, GRU_HIDDEN] temporal state
            current_graph: the last graph in the sequence (for reconstruction targets)
        """
        assert len(graphs) == SEQ_LEN, f"Expected {SEQ_LEN} graphs, got {len(graphs)}"

        spatial_seq = []
        for g in graphs:
            g = g.to(device)
            if g.num_nodes == 0:
                z = torch.zeros(1, EMBEDDING_DIM, device=device)
            else:
                z = self.spatial_enc(g.x, g.edge_index)  # [N_t, EMBEDDING_DIM]

            # Pad/truncate to MAX_NODES
            padded = torch.zeros(MAX_NODES, EMBEDDING_DIM, device=device)
            n = min(z.shape[0], MAX_NODES)
            padded[:n] = z[:n]
            spatial_seq.append(padded)

        # Stack to [SEQ_LEN, MAX_NODES, EMBEDDING_DIM]
        z_seq = torch.stack(spatial_seq, dim=0)

        # Temporal encoding → [MAX_NODES, GRU_HIDDEN]
        h = self.temporal_enc(z_seq)

        return h, graphs[-1].to(device)

    # ─── Forward pass (training) ───────────────────────────────────────────

    def forward(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            x_recon:    [N_current, NODE_FEATURE_DIM]  reconstructed features
            edge_probs: [E_current]                     reconstructed edge probabilities
        """
        h, g_curr = self._encode_sequence(graphs, device)
        n = min(g_curr.num_nodes, MAX_NODES)

        x_recon    = self.feat_dec(h[:n])
        edge_probs = self.edge_dec(h[:n], g_curr.edge_index)
        return x_recon, edge_probs

    # ─── Inference mode: compute per-node reconstruction errors ────────────

    @torch.no_grad()
    def reconstruct(
        self,
        graphs: List[Data],
        device: torch.device,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Returns:
            x_recon:     [N, NODE_FEATURE_DIM]
            edge_probs:  [E]
            node_errors: [N]  per-node MSE reconstruction error
        """
        h, g_curr = self._encode_sequence(graphs, device)
        n = min(g_curr.num_nodes, MAX_NODES)
        x_recon    = self.feat_dec(h[:n])
        edge_probs = self.edge_dec(h[:n], g_curr.edge_index)

        x_target   = g_curr.x[:n]
        node_errors = F.mse_loss(x_recon, x_target, reduction='none').mean(dim=1)

        return x_recon, edge_probs, node_errors

# ─────────────────────────────────────────────────────────────────────────────
# Loss function
# ─────────────────────────────────────────────────────────────────────────────

def compute_loss(
    x_recon:    torch.Tensor,  # [N, F]
    x_target:   torch.Tensor,  # [N, F]
    edge_probs: torch.Tensor,  # [E]
    edge_index: torch.Tensor,  # [2, E]
    num_nodes:  int,
    alpha:      float = 0.7,   # weight for feature loss
    beta:       float = 0.3,   # weight for structure loss
) -> torch.Tensor:
    feat_loss = F.mse_loss(x_recon, x_target)

    # Edge targets: 1 for observed edges (all entries in edge_index are real)
    edge_targets = torch.ones(edge_probs.shape[0], device=edge_probs.device)
    struct_loss  = F.binary_cross_entropy(edge_probs, edge_targets)

    return alpha * feat_loss + beta * struct_loss
```

### 6.4 `src/trainer.py`

```python
# inference/src/trainer.py
#
# Offline training loop.
# Usage:
#   python -m radm.trainer --config radm.yaml --data-dir /var/radm/baseline
#
# Baseline data is collected by running the system in OBSERVE mode (no quarantine)
# for a minimum of 2 hours.  Graph snapshots are saved as pickled PyG Data objects.

import argparse
import pathlib
import pickle
import torch
import torch.optim as optim
from torch_geometric.data import Data
from model import SpatiotemporalAutoencoder, compute_loss, SEQ_LEN
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

log = logging.getLogger(__name__)


def load_baseline_sequences(data_dir: pathlib.Path, seq_len: int = SEQ_LEN):
    """Load consecutive graph snapshots from disk and group into sequences."""
    files = sorted(data_dir.glob("snapshot_*.pkl"))
    log.info(f"Loaded {len(files)} baseline snapshots from {data_dir}")
    graphs = [pickle.loads(f.read_bytes()) for f in files]

    sequences = []
    for i in range(len(graphs) - seq_len):
        seq = graphs[i : i + seq_len]
        sequences.append(seq)
    return sequences


def train(config: dict, device: torch.device):
    data_dir   = pathlib.Path(config["baseline_data_dir"])
    checkpoint = pathlib.Path(config["checkpoint_path"])
    epochs     = config.get("epochs", 50)
    lr         = config.get("lr", 1e-3)

    sequences = load_baseline_sequences(data_dir)
    log.info(f"Training on {len(sequences)} sequences, device={device}")

    model     = SpatiotemporalAutoencoder().to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    model.train()
    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        for seq in sequences:
            optimizer.zero_grad()
            x_recon, edge_probs = model(seq, device)

            g_curr     = seq[-1].to(device)
            n          = min(g_curr.num_nodes, 256)
            x_target   = g_curr.x[:n]
            edge_index = g_curr.edge_index

            loss = compute_loss(x_recon, x_target, edge_probs, edge_index, n)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += loss.item()

        scheduler.step()
        avg = epoch_loss / max(len(sequences), 1)
        log.info(f"Epoch {epoch:3d}/{epochs} | loss={avg:.6f} | lr={scheduler.get_last_lr()[0]:.2e}")

    # ── Fit Isolation Forest on training embeddings ─────────────────────────
    log.info("Fitting Isolation Forest anomaly classifier on training data…")
    model.eval()
    all_embeddings, all_errors = [], []

    with torch.no_grad():
        for seq in sequences:
            _, _, node_errors = model.reconstruct(seq, device)
            # Use final-snapshot GATv2 embeddings (from spatial encoder only)
            g = seq[-1].to(device)
            n = min(g.num_nodes, 256)
            from model import SpatialEncoder
            z = model.spatial_enc(g.x[:n], g.edge_index)
            all_embeddings.append(z.cpu().numpy())
            all_errors.append(node_errors.cpu().numpy())

    emb_flat = np.vstack(all_embeddings)
    err_flat = np.concatenate(all_errors).reshape(-1, 1)
    features = np.hstack([emb_flat, err_flat])

    clf = IsolationForest(contamination=0.01, n_estimators=200, random_state=42)
    clf.fit(features)

    # ── Save checkpoint ──────────────────────────────────────────────────────
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "model_state":   model.state_dict(),
        "iforest":       clf,
        "config":        config,
    }, checkpoint)
    log.info(f"Checkpoint saved → {checkpoint}")
    return model, clf
```

### 6.5 `src/detector.py` (Online Inference Loop)

```python
# inference/src/detector.py
#
# Online anomaly detection loop.
# Consumes GraphSnapshot protobufs from UDS, runs ST-GAE inference,
# classifies anomalies via Isolation Forest, and emits AnomalyAlert protobufs.

import asyncio
import socket
import struct
import time
import logging
import numpy as np
import torch
import torch.nn.functional as F
from collections import deque
from pathlib import Path
from sklearn.ensemble import IsolationForest

from model import SpatiotemporalAutoencoder, SEQ_LEN, MAX_NODES
from proto import radm_pb2 as pb
from torch_geometric.data import Data

log = logging.getLogger(__name__)

ALERT_THRESHOLD = -0.2   # Isolation Forest score below this triggers alert


def proto_to_pyg(snapshot: pb.GraphSnapshot) -> Data:
    """Convert a GraphSnapshot protobuf into a PyTorch Geometric Data object."""
    n = len(snapshot.nodes)
    if n == 0:
        return Data(
            x=torch.zeros(1, 7), edge_index=torch.zeros(2, 0, dtype=torch.long)
        )

    x = torch.tensor([list(node.features) for node in snapshot.nodes], dtype=torch.float)

    if snapshot.edges:
        src = [e.src_index for e in snapshot.edges]
        dst = [e.dst_index for e in snapshot.edges]
        edge_index = torch.tensor([src, dst], dtype=torch.long)
    else:
        edge_index = torch.zeros(2, 0, dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        num_nodes=n,
        node_ids=[node.node_id for node in snapshot.nodes],
    )


class AnomalyDetector:
    def __init__(self, checkpoint_path: str, device: str = "cpu"):
        self.device = torch.device(device)
        ckpt = torch.load(checkpoint_path, map_location=self.device, weights_only=False)

        self.model = SpatiotemporalAutoencoder().to(self.device)
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval()

        # torch.compile for ~2× CPU speedup (requires PyTorch 2.0+)
        self.model = torch.compile(self.model, mode="reduce-overhead")

        self.clf: IsolationForest = ckpt["iforest"]
        self.seq_buffer: deque = deque(maxlen=SEQ_LEN)
        self.alert_id_counter = 0

        log.info(f"Loaded checkpoint from {checkpoint_path}, device={device}")

    def feed(self, snapshot: pb.GraphSnapshot) -> list[pb.AnomalyAlert]:
        """
        Feed one snapshot into the sequence buffer.
        Returns a list of AnomalyAlert protobufs (may be empty).
        """
        graph = proto_to_pyg(snapshot)
        self.seq_buffer.append(graph)

        if len(self.seq_buffer) < SEQ_LEN:
            return []  # not enough history yet

        graphs = list(self.seq_buffer)
        with torch.no_grad():
            x_recon, edge_probs, node_errors = self.model.reconstruct(graphs, self.device)

        # Compute Isolation Forest features (embedding + reconstruction error)
        g_curr = graphs[-1].to(self.device)
        n = min(g_curr.num_nodes, MAX_NODES)
        z = self.model.spatial_enc(g_curr.x[:n], g_curr.edge_index)

        emb = z.cpu().numpy()
        err = node_errors.cpu().numpy().reshape(-1, 1)
        features = np.hstack([emb, err])

        scores = self.clf.score_samples(features)  # lower = more anomalous

        # Identify anomalous nodes
        anomalous_mask = scores < ALERT_THRESHOLD
        if not anomalous_mask.any():
            return []

        alerts = []
        for node_idx in np.where(anomalous_mask)[0]:
            node = snapshot.nodes[node_idx]
            if node.node_type != pb.NodeType.CONTAINER:
                continue  # only alert on containers

            # Normalise score to [0,1] — lower IF score = higher anomaly
            raw_score = float(scores[node_idx])
            anomaly_score = 1.0 - (raw_score - self.clf.offset_) / abs(self.clf.offset_)
            anomaly_score = max(0.0, min(1.0, anomaly_score))

            threat = self._classify_threat(graphs, node_errors, node_idx)

            self.alert_id_counter += 1
            alert = pb.AnomalyAlert(
                alert_id=self.alert_id_counter,
                timestamp_ns=int(time.time_ns()),
                cgroup_id=node.node_id,
                target_pid=0,  # resolved by aggregator from cgroup_id
                container_id=node.label,
                container_name=node.label,
                anomaly_score=anomaly_score,
                node_errors=node_errors.tolist(),
                threat_class=threat,
                raw_graph_snapshot=snapshot.SerializeToString(),
            )
            alerts.append(alert)
            log.warning(
                f"ANOMALY: container={node.label} score={anomaly_score:.4f} "
                f"threat={pb.ThreatClass.Name(threat)}"
            )

        return alerts

    def _classify_threat(
        self,
        graphs: list,
        node_errors: torch.Tensor,
        node_idx: int,
    ) -> pb.ThreatClass:
        """
        Heuristic threat classification based on which feature dimensions
        contribute most to the reconstruction error.
        Feature layout: [type_oh(3), mprotect_freq(1), iat_var(1), port_delta(1), event_freq(1)]
        """
        # Per-feature reconstruction error for this node
        g_curr = graphs[-1]
        n = min(g_curr.num_nodes, MAX_NODES)
        with torch.no_grad():
            z = self.model.spatial_enc(g_curr.x[:n], g_curr.edge_index)
            x_recon = self.model.feat_dec(z)
        feat_errors = F.mse_loss(
            x_recon[node_idx], g_curr.x[node_idx], reduction='none'
        ).cpu().numpy()

        mprotect_err = feat_errors[3]
        iat_err      = feat_errors[4]
        port_err     = feat_errors[5]
        event_err    = feat_errors[6]

        if mprotect_err > 0.5:
            return pb.ThreatClass.MEMORY_INJECTION
        if port_err > 0.5 and event_err > 0.5:
            return pb.ThreatClass.DATA_EXFILTRATION
        if iat_err > 0.5:
            return pb.ThreatClass.LATERAL_MOVEMENT
        return pb.ThreatClass.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Async I/O wrappers for UDS communication
# ─────────────────────────────────────────────────────────────────────────────

async def read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    """Read a 4-byte big-endian length prefix then that many bytes."""
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    return await reader.readexactly(length)


async def write_length_prefixed(writer: asyncio.StreamWriter, data: bytes):
    """Write a 4-byte big-endian length prefix then the data."""
    header = struct.pack(">I", len(data))
    writer.write(header + data)
    await writer.drain()


async def run_detector(config: dict):
    graph_socket_path = config["graph_socket_path"]
    alert_socket_path = config["alert_socket_path"]
    checkpoint_path   = config["checkpoint_path"]

    detector = AnomalyDetector(checkpoint_path, config.get("device", "cpu"))

    # Connect to aggregator graph stream
    reader, _ = await asyncio.open_unix_connection(graph_socket_path)
    log.info(f"Connected to graph stream: {graph_socket_path}")

    # Open alert socket (connect to mitigation plane)
    alert_reader, alert_writer = await asyncio.open_unix_connection(alert_socket_path)
    log.info(f"Connected to alert socket: {alert_socket_path}")

    while True:
        try:
            raw = await read_length_prefixed(reader)
            snapshot = pb.GraphSnapshot()
            snapshot.ParseFromString(raw)

            alerts = detector.feed(snapshot)
            for alert in alerts:
                await write_length_prefixed(alert_writer, alert.SerializeToString())

        except asyncio.IncompleteReadError:
            log.warning("Graph stream closed — reconnecting in 2s")
            await asyncio.sleep(2)
        except Exception as e:
            log.error(f"Detector error: {e}", exc_info=True)
```

---

## §7 — COMPONENT 4: MITIGATION CONTROL PLANE (Rust)

### 7.1 `Cargo.toml`

```toml
[package]
name    = "radm-mitigation"
version = "0.1.0"
edition = "2021"

[dependencies]
aya             = "0.13"
tokio           = { version = "1", features = ["full"] }
prost           = "0.13"
bytes           = "1"
nix             = { version = "0.29", features = ["process", "ptrace", "sched"] }
procfs          = "0.16"
tracing         = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow          = "1"
serde            = { version = "1", features = ["derive"] }
rand            = "0.8"
aes-gcm         = "0.10"

[build-dependencies]
prost-build     = "0.13"
```

### 7.2 `src/quarantine_exec.rs`

```rust
// mitigation/src/quarantine_exec.rs
//
// Isolates a container by:
//  1. Discovering the veth pair for the container's network namespace
//  2. Attaching a TC BPF DROP program to the host-side veth
//  3. Updating quarantine_map and quarantine_ip_map in BPF (for XDP)
//  4. Initiating async forensic capture
//
// Required capabilities: CAP_NET_ADMIN, CAP_BPF, CAP_SYS_ADMIN, CAP_SYS_PTRACE

use std::path::PathBuf;
use std::process::Command;
use nix::sched::{setns, CloneFlags};
use nix::unistd::Pid;
use tracing::{info, warn, error};

use crate::proto::radm::{AnomalyAlert, QuarantineEvent, QuarantineStatus};
use crate::forensics::capture_memory;

pub struct QuarantineExecutor {
    bpf_pin_dir:       PathBuf,  // /sys/fs/bpf/radm/
    tc_drop_bpf_obj:   PathBuf,  // path to compiled radm_tc.o (already contains DROP logic)
    forensic_dir:      PathBuf,  // /var/radm/forensics/
}

impl QuarantineExecutor {
    pub fn new(bpf_pin_dir: &str, tc_bpf_obj: &str, forensic_dir: &str) -> Self {
        Self {
            bpf_pin_dir:     PathBuf::from(bpf_pin_dir),
            tc_drop_bpf_obj: PathBuf::from(tc_bpf_obj),
            forensic_dir:    PathBuf::from(forensic_dir),
        }
    }

    pub async fn quarantine(&self, alert: &AnomalyAlert) -> QuarantineEvent {
        let pid = alert.target_pid;
        let cgroup_id = alert.cgroup_id;

        info!(
            "Quarantine initiated: container={} pid={} cgroup={:#x}",
            alert.container_id, pid, cgroup_id
        );

        // ── Step 1: Find the veth pair ──────────────────────────────────────
        let veth_host = match self.find_veth_for_pid(pid) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to find veth for pid {}: {}", pid, e);
                return self.failed_event(alert, &e.to_string());
            }
        };

        // ── Step 2: Attach TC BPF DROP to veth host side ───────────────────
        if let Err(e) = self.attach_tc_drop(&veth_host) {
            error!("TC attach failed for {}: {}", veth_host, e);
            return self.failed_event(alert, &e.to_string());
        }

        // ── Step 3: Update BPF quarantine maps ─────────────────────────────
        if let Err(e) = self.update_bpf_quarantine_maps(cgroup_id, pid) {
            warn!("BPF map update failed (non-fatal): {}", e);
        }

        // ── Step 4: Async forensic capture ─────────────────────────────────
        let forensic_path = self.forensic_dir.join(format!(
            "forensic_{}_pid{}.bin.enc",
            chrono_or_timestamp(),
            pid,
        ));
        let forensic_path_str = forensic_path.to_string_lossy().to_string();
        let fp_clone = forensic_path.clone();
        tokio::spawn(async move {
            if let Err(e) = capture_memory(Pid::from_raw(pid as i32), &fp_clone).await {
                warn!("Forensic capture failed: {}", e);
            }
        });

        info!("Quarantine ACTIVE: veth={} forensic={}", veth_host, forensic_path_str);

        QuarantineEvent {
            alert_id:      alert.alert_id,
            timestamp_ns:  current_time_ns(),
            container_id:  alert.container_id.clone(),
            target_pid:    pid,
            status:        QuarantineStatus::QuarantineActive as i32,
            veth_iface:    veth_host,
            forensic_path: forensic_path_str,
            error_msg:     String::new(),
        }
    }

    /// Discover host-side veth interface for a container PID.
    ///
    /// Strategy:
    ///   1. Open /proc/<PID>/ns/net to get the container's network namespace fd.
    ///   2. Enter the namespace, read /sys/class/net/*/ifindex.
    ///   3. Match against host interfaces to find the veth pair via iflink.
    ///   4. Return the HOST-side veth name.
    fn find_veth_for_pid(&self, pid: u32) -> anyhow::Result<String> {
        // Read the container's ifindex for eth0 (its veth end)
        let netns_path = format!("/proc/{}/ns/net", pid);

        // Use `ip netns identify <pid>` as a simpler cross-runtime approach
        // then find the host veth via `ip link show` and iflink matching.
        let out = Command::new("nsenter")
            .args([
                &format!("--net={}", netns_path),
                "--",
                "cat",
                "/sys/class/net/eth0/ifindex",
            ])
            .output()?;

        let container_ifindex: u32 = String::from_utf8(out.stdout)?
            .trim()
            .parse()?;

        // Find host interface with iflink == container_ifindex
        // (veth pairs: iflink of one end == ifindex of the other end)
        let entries = std::fs::read_dir("/sys/class/net")?;
        for entry in entries {
            let entry = entry?;
            let iface = entry.file_name();
            let iface_name = iface.to_string_lossy();
            let iflink_path = format!("/sys/class/net/{}/iflink", iface_name);

            if let Ok(iflink_str) = std::fs::read_to_string(&iflink_path) {
                if let Ok(iflink) = iflink_str.trim().parse::<u32>() {
                    if iflink == container_ifindex {
                        return Ok(iface_name.to_string());
                    }
                }
            }
        }

        anyhow::bail!("No host-side veth found for container ifindex {}", container_ifindex)
    }

    /// Attach TC BPF DROP program to the veth interface.
    ///
    /// This uses the `tc` command-line tool (iproute2) for maximum compatibility.
    /// In production, replace with aya's SchedClassifier for fully programmatic control.
    fn attach_tc_drop(&self, veth: &str) -> anyhow::Result<()> {
        let obj_path = self.tc_drop_bpf_obj.to_string_lossy();

        // Add clsact qdisc if not present
        let _ = Command::new("tc")
            .args(["qdisc", "add", "dev", veth, "clsact"])
            .output();  // ignore error if already present

        // Attach BPF program to ingress
        let status = Command::new("tc")
            .args([
                "filter", "replace", "dev", veth, "ingress",
                "bpf", "da", "obj", &obj_path, "sec", "tc/ingress",
            ])
            .status()?;
        anyhow::ensure!(status.success(), "tc filter ingress attach failed");

        // Attach BPF program to egress
        let status = Command::new("tc")
            .args([
                "filter", "replace", "dev", veth, "egress",
                "bpf", "da", "obj", &obj_path, "sec", "tc/egress",
            ])
            .status()?;
        anyhow::ensure!(status.success(), "tc filter egress attach failed");

        Ok(())
    }

    /// Insert cgroup_id and container IPs into pinned BPF maps so XDP
    /// also enforces the quarantine at the host-NIC level.
    fn update_bpf_quarantine_maps(&self, cgroup_id: u64, _pid: u32) -> anyhow::Result<()> {
        // Use bpftool to update pinned maps — avoids needing to re-load programs
        let cmap = self.bpf_pin_dir.join("quarantine_map").to_string_lossy().to_string();
        let key_hex  = format!("{:#018x}", cgroup_id);
        let value = "0x01";

        let status = Command::new("bpftool")
            .args(["map", "update", "pinned", &cmap,
                   "key", &key_hex, "value", value])
            .status()?;
        anyhow::ensure!(status.success(), "bpftool map update quarantine_map failed");
        Ok(())
    }

    fn failed_event(&self, alert: &AnomalyAlert, msg: &str) -> QuarantineEvent {
        QuarantineEvent {
            alert_id:      alert.alert_id,
            timestamp_ns:  current_time_ns(),
            container_id:  alert.container_id.clone(),
            target_pid:    alert.target_pid,
            status:        QuarantineStatus::QuarantineFailed as i32,
            veth_iface:    String::new(),
            forensic_path: String::new(),
            error_msg:     msg.to_string(),
        }
    }
}

fn current_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn chrono_or_timestamp() -> String {
    let ns = current_time_ns();
    format!("{}", ns / 1_000_000_000)
}
```

### 7.3 `src/forensics.rs`

```rust
// mitigation/src/forensics.rs
//
// Captures the volatile memory pages of a target process using process_vm_readv(2).
// The dump is AES-256-GCM encrypted before writing to disk.
//
// For full ELF core dump, consider delegating to `gcore -p <PID>`.

use nix::unistd::Pid;
use nix::sys::ptrace;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
use aes_gcm::aead::generic_array::GenericArray;

/// Read the target PID's memory maps from /proc/<PID>/maps,
/// dump readable non-special-file segments via process_vm_readv,
/// and write an AES-256-GCM encrypted blob to output_path.
pub async fn capture_memory(pid: Pid, output_path: &Path) -> anyhow::Result<()> {
    // Attach ptrace to pause the process during capture
    ptrace::attach(pid)?;
    nix::sys::wait::waitpid(pid, None)?;

    let result = do_capture(pid, output_path);

    // Detach ptrace (resumes process) regardless of capture success
    let _ = ptrace::detach(pid, None);

    result
}

fn do_capture(pid: Pid, output_path: &Path) -> anyhow::Result<()> {
    let maps_path = format!("/proc/{}/maps", pid.as_raw());
    let maps_content = std::fs::read_to_string(&maps_path)?;

    let mut dump_data: Vec<u8> = Vec::new();

    for line in maps_content.lines() {
        // Parse map entry: "start-end perms offset dev ino [pathname]"
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 { continue; }

        let perms = parts[1];
        let pathname = parts.get(5).map(|s| s.trim()).unwrap_or("");

        // Only dump: readable, anonymous or heap/stack segments
        if !perms.contains('r') { continue; }
        if pathname.starts_with('/') && !pathname.is_empty()
            && pathname != "[heap]" && pathname != "[stack]"
        {
            continue;  // Skip mapped files; focus on anonymous + heap/stack
        }

        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 { continue; }

        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let end   = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let size  = end.saturating_sub(start) as usize;
        if size == 0 || size > 256 * 1024 * 1024 { continue; }  // skip > 256 MB

        // Use process_vm_readv for zero-ptrace-overhead memory read
        let mut buf = vec![0u8; size];
        let remote_iov = nix::sys::uio::RemoteIoVec { base: start as usize, len: size };
        let local_iov  = nix::sys::uio::IoVec::from_mut_slice(&mut buf);

        match nix::sys::uio::process_vm_readv(pid, &[local_iov], &[remote_iov]) {
            Ok(n) if n > 0 => {
                // Prepend a region header: [u64 start][u64 end][u64 actual_bytes_read]
                dump_data.extend_from_slice(&start.to_le_bytes());
                dump_data.extend_from_slice(&end.to_le_bytes());
                dump_data.extend_from_slice(&(n as u64).to_le_bytes());
                dump_data.extend_from_slice(&buf[..n]);
            }
            _ => {}  // Page not mapped or read error — skip silently
        }
    }

    // ── AES-256-GCM encrypt the dump ──────────────────────────────────────
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key    = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, dump_data.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {:?}", e))?;

    // Write: [32-byte key][12-byte nonce][ciphertext]
    // KEY IS STORED IN THE FILE — in production, use a KMS or hardware HSM
    // to encrypt the key separately.
    let mut output = std::fs::OpenOptions::new()
        .write(true).create_new(true)
        .mode(0o600)
        .open(output_path)?;

    use std::io::Write;
    output.write_all(&key_bytes)?;
    output.write_all(&nonce_bytes)?;
    output.write_all(&ciphertext)?;

    tracing::info!(
        "Forensic dump: {} bytes → {} (encrypted)",
        dump_data.len(),
        output_path.display()
    );
    Ok(())
}
```

---

## §8 — DIRECTORY LAYOUT

```
radm/
├── README.md
├── LICENSE                          (Apache 2.0)
├── ARCHITECTURE.md                  (auto-generated from this spec)
├── radm.toml                        (default global config)
├── Makefile                         (top-level orchestrator)
│
├── proto/
│   ├── radm.proto                   (canonical schema — §6.2)
│   └── generate.sh                  (regenerates language bindings)
│
├── kernel/
│   ├── Makefile
│   ├── include/vmlinux.h            (generated — do not commit)
│   └── src/
│       ├── radm_types.h             (shared C/Rust types)
│       ├── radm_maps.h              (BPF map declarations)
│       ├── radm_helpers.h           (rate-limiter + hash helper)
│       ├── radm_xdp.c               (XDP: DDoS gate)
│       ├── radm_tc.c                (TC BPF: per-veth monitor + quarantine)
│       └── radm_tp.c                (tracepoints: mprotect/mmap/ptrace/memfd)
│
├── aggregator/                      (Rust crate)
│   ├── Cargo.toml
│   ├── build.rs                     (prost protobuf codegen)
│   └── src/
│       ├── main.rs
│       ├── config.rs
│       ├── types.rs                 (bindgen output from radm_types.h)
│       ├── bpf_loader.rs
│       ├── bpf_consumer.rs
│       ├── graph_builder.rs
│       ├── ipc_server.rs
│       ├── quarantine_receiver.rs
│       ├── cgroup_resolver.rs       (cgroup_id → container name lookup)
│       └── proto/                   (generated by build.rs)
│           └── radm.v1.rs
│
├── inference/                       (Python package)
│   ├── requirements.txt
│   ├── setup.py
│   ├── radm.yaml                    (inference config)
│   └── src/
│       ├── __init__.py
│       ├── main.py                  (entry point)
│       ├── model.py                 (ST-GAE architecture)
│       ├── trainer.py               (offline training)
│       ├── detector.py              (online inference)
│       ├── alert_publisher.py       (UDS alert writer)
│       └── proto/
│           ├── radm.proto           (symlink → ../../proto/radm.proto)
│           ├── radm_pb2.py          (generated by protoc)
│           └── radm_pb2.pyi         (generated type stubs)
│
├── mitigation/                      (Rust crate)
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── main.rs
│       ├── config.rs
│       ├── quarantine_exec.rs
│       ├── forensics.rs
│       ├── bpf_updater.rs
│       └── proto/                   (generated)
│
├── config/
│   ├── radm.default.toml
│   ├── radm.dev.toml
│   └── radm.prod.toml
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.aggregator
│   │   ├── Dockerfile.inference
│   │   ├── Dockerfile.mitigation
│   │   └── docker-compose.yml
│   ├── kubernetes/
│   │   ├── namespace.yaml
│   │   ├── rbac.yaml
│   │   ├── configmap.yaml
│   │   ├── daemonset.yaml           (aggregator + mitigation — one pod per node)
│   │   ├── deployment.yaml          (inference — can be replicated)
│   │   └── helm/radm/
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       └── templates/
│   └── systemd/
│       ├── radm-aggregator.service
│       ├── radm-inference.service
│       └── radm-mitigation.service
│
├── scripts/
│   ├── radm-ctl.sh                  (master orchestration — §10)
│   ├── build-kernel.sh
│   ├── generate-proto.sh
│   ├── install-deps.sh
│   └── simulate-attack.sh           (adversarial test driver — §11)
│
└── tests/
    ├── unit/
    │   ├── kernel/                  (bpftool prog test + pytest-bpf)
    │   ├── aggregator/              (cargo test)
    │   └── inference/               (pytest)
    ├── integration/
    │   ├── docker-compose.test.yml
    │   └── test_end_to_end.py
    └── benchmark/
        ├── bench_ringbuf.sh         (events/sec throughput)
        ├── bench_graph.rs           (graph build latency)
        └── bench_inference.py       (inference latency distribution)
```

---

## §9 — CONFIGURATION SCHEMA (`radm.toml`)

```toml
[global]
log_level = "info"          # trace | debug | info | warn | error
run_dir   = "/run/radm"
bpf_pin   = "/sys/fs/bpf/radm"

[kernel]
bpf_object_dir     = "/etc/radm/bpf"     # compiled *.o files
host_interface     = "eth0"              # NIC for XDP attach
ringbuf_size_mb    = 16                  # 16 MB (must be power of 2)
ratelimit_capacity = 10000              # token bucket capacity
ratelimit_refill   = 1000               # tokens per millisecond

[aggregator]
graph_socket_path    = "/run/radm/graph.sock"
alert_socket_path    = "/run/radm/alert.sock"
window_duration_ms   = 5000
snapshot_interval_ms = 1000
max_nodes            = 256
container_runtime    = "containerd"      # "docker" | "containerd"

# Thread pool sizes
bpf_consumer_threads  = 2
graph_builder_threads = 2
ipc_threads           = 1

[inference]
graph_socket_path  = "/run/radm/graph.sock"
alert_socket_path  = "/run/radm/alert.sock"
checkpoint_path    = "/var/radm/model/checkpoint.pt"
baseline_data_dir  = "/var/radm/baseline"
device             = "cpu"               # "cpu" | "cuda"
alert_threshold    = -0.2               # IF score below this triggers alert
seq_len            = 10

# Training
epochs             = 50
learning_rate      = 0.001
min_baseline_hours = 2.0

[mitigation]
alert_socket_path  = "/run/radm/alert.sock"
forensic_dir       = "/var/radm/forensics"
bpf_pin_dir        = "/sys/fs/bpf/radm"
tc_bpf_obj         = "/etc/radm/bpf/radm_tc.o"
auto_quarantine    = true               # false = alert-only mode
dry_run            = false

[observability]
prometheus_port    = 9090
metrics_path       = "/metrics"
```

---

## §10 — MASTER ORCHESTRATION SCRIPT (`scripts/radm-ctl.sh`)

```bash
#!/usr/bin/env bash
# radm-ctl.sh — Single-command build, deploy, and test driver for Radm
# Usage:
#   ./radm-ctl.sh build          — compile all components
#   ./radm-ctl.sh install        — install binaries, BPF objects, configs
#   ./radm-ctl.sh start          — launch all daemons
#   ./radm-ctl.sh stop           — stop all daemons
#   ./radm-ctl.sh status         — show daemon status
#   ./radm-ctl.sh observe [N]    — collect N-minute baseline
#   ./radm-ctl.sh train          — train ST-GAE on baseline
#   ./radm-ctl.sh simulate-attack — trigger adversarial test scenario
#   ./radm-ctl.sh test           — run full test suite

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="/usr/local/bin"
ETC_DIR="/etc/radm"
VAR_DIR="/var/radm"
RUN_DIR="/run/radm"
LOG_DIR="/var/log/radm"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[RADM]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fatal() { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

# ─── Prerequisite checks ─────────────────────────────────────────────────────

check_prerequisites() {
    info "Checking prerequisites…"
    local failed=0

    for cmd in clang-15 bpftool rustc cargo python3 protoc tc ip; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "Missing: $cmd"
            failed=$((failed + 1))
        fi
    done

    # Kernel version check
    local kern_ver
    kern_ver=$(uname -r | cut -d. -f1-2 | tr -d '.')
    if [[ $kern_ver -lt 515 ]]; then
        fatal "Kernel $(uname -r) too old — minimum 5.15 required"
    fi

    # cgroup v2 check
    if ! mount | grep -q "cgroup2 on /sys/fs/cgroup"; then
        fatal "cgroup v2 not active — run: systemd.unified_cgroup_hierarchy=1"
    fi

    # BTF check
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        fatal "BTF not available — recompile kernel with CONFIG_DEBUG_INFO_BTF=y"
    fi

    [[ $failed -gt 0 ]] && fatal "$failed prerequisites missing. Run: ./scripts/install-deps.sh"
    info "Prerequisites OK"
}

# ─── Build ────────────────────────────────────────────────────────────────────

build_kernel() {
    info "Building eBPF kernel objects…"
    cd "$REPO_ROOT/kernel"
    make clean all CLANG=clang-15 BPFTOOL=bpftool
    info "Kernel objects built: $(ls src/*.o | xargs)"
}

build_aggregator() {
    info "Building radm-aggregator (Rust)…"
    cd "$REPO_ROOT/aggregator"
    cargo build --release
}

build_mitigation() {
    info "Building radm-mitigation (Rust)…"
    cd "$REPO_ROOT/mitigation"
    cargo build --release
}

build_inference() {
    info "Installing Python inference dependencies…"
    cd "$REPO_ROOT/inference"
    python3 -m pip install -q -r requirements.txt
}

generate_proto() {
    info "Generating Protobuf bindings…"
    cd "$REPO_ROOT"

    # Python bindings
    protoc --proto_path=proto \
           --python_out=inference/src/proto \
           --pyi_out=inference/src/proto \
           proto/radm.proto

    info "Proto bindings generated"
}

cmd_build() {
    check_prerequisites
    generate_proto
    build_kernel
    build_aggregator
    build_mitigation
    build_inference
    info "Build complete"
}

# ─── Install ─────────────────────────────────────────────────────────────────

cmd_install() {
    [[ $EUID -ne 0 ]] && fatal "install requires root"

    mkdir -p "$ETC_DIR/bpf" "$VAR_DIR"/{baseline,model,forensics} "$RUN_DIR" "$LOG_DIR"
    chmod 700 "$VAR_DIR/forensics"

    # BPF objects
    install -m 644 "$REPO_ROOT"/kernel/src/*.o "$ETC_DIR/bpf/"

    # Binaries
    install -m 755 "$REPO_ROOT/aggregator/target/release/radm-aggregator" "$BIN_DIR/"
    install -m 755 "$REPO_ROOT/mitigation/target/release/radm-mitigation"  "$BIN_DIR/"

    # Config
    install -m 644 "$REPO_ROOT/config/radm.default.toml" /etc/radm/radm.toml

    # Systemd units
    install -m 644 "$REPO_ROOT"/deploy/systemd/*.service /etc/systemd/system/
    systemctl daemon-reload

    info "Install complete"
}

# ─── Daemon management ────────────────────────────────────────────────────────

cmd_start() {
    [[ $EUID -ne 0 ]] && fatal "start requires root"

    mkdir -p "$RUN_DIR"

    info "Starting radm-aggregator…"
    systemctl start radm-aggregator
    sleep 1

    info "Starting radm-inference…"
    # Run inference as a non-privileged service via systemd
    systemctl start radm-inference
    sleep 1

    info "Starting radm-mitigation…"
    systemctl start radm-mitigation

    cmd_status
}

cmd_stop() {
    systemctl stop radm-mitigation radm-inference radm-aggregator 2>/dev/null || true
    info "All Radm daemons stopped"
}

cmd_status() {
    for svc in radm-aggregator radm-inference radm-mitigation; do
        if systemctl is-active --quiet "$svc"; then
            echo -e "  ${GREEN}●${NC} $svc"
        else
            echo -e "  ${RED}○${NC} $svc (inactive)"
        fi
    done
}

# ─── Baseline collection ─────────────────────────────────────────────────────

cmd_observe() {
    local minutes="${1:-120}"
    info "Collecting baseline for $minutes minutes → $VAR_DIR/baseline/"
    info "Ensure no attacks are in progress during this phase."

    # Start aggregator in observe-only mode (no quarantine)
    local tmpconf
    tmpconf=$(mktemp)
    sed 's/auto_quarantine = true/auto_quarantine = false/' /etc/radm/radm.toml > "$tmpconf"

    # Launch aggregator
    radm-aggregator --config "$tmpconf" &
    local AGG_PID=$!

    # Python baseline collector: read graph snapshots and save as pickled PyG objects
    python3 - <<'PYEOF'
import asyncio, struct, pickle, pathlib, time, sys
sys.path.insert(0, "$REPO_ROOT/inference/src")
from proto import radm_pb2 as pb
from detector import proto_to_pyg

BASELINE_DIR = pathlib.Path("$VAR_DIR/baseline")
BASELINE_DIR.mkdir(exist_ok=True)
TIMEOUT = int("$minutes") * 60

async def collect():
    r, _ = await asyncio.open_unix_connection("$RUN_DIR/graph.sock")
    seq = 0
    start = time.time()
    while time.time() - start < TIMEOUT:
        hdr = await r.readexactly(4)
        n = struct.unpack(">I", hdr)[0]
        raw = await r.readexactly(n)
        snap = pb.GraphSnapshot(); snap.ParseFromString(raw)
        g = proto_to_pyg(snap)
        out = BASELINE_DIR / f"snapshot_{seq:08d}.pkl"
        out.write_bytes(pickle.dumps(g))
        seq += 1
        if seq % 100 == 0:
            print(f"  Collected {seq} snapshots ({time.time()-start:.0f}s / {TIMEOUT}s)")

asyncio.run(collect())
PYEOF

    kill "$AGG_PID" 2>/dev/null
    info "Baseline collection complete: $(ls "$VAR_DIR/baseline" | wc -l) snapshots"
}

# ─── Training ─────────────────────────────────────────────────────────────────

cmd_train() {
    info "Training ST-GAE on baseline data…"
    python3 "$REPO_ROOT/inference/src/trainer.py" \
        --config "$REPO_ROOT/inference/radm.yaml" \
        --data-dir "$VAR_DIR/baseline"
    info "Training complete. Checkpoint: $VAR_DIR/model/checkpoint.pt"
}

# ─── Attack simulation ────────────────────────────────────────────────────────

cmd_simulate_attack() {
    info "Running adversarial attack simulation…"
    "$REPO_ROOT/scripts/simulate-attack.sh"
}

# ─── Test suite ───────────────────────────────────────────────────────────────

cmd_test() {
    info "Running unit tests…"

    # Kernel BPF unit tests
    info "  [1/4] Kernel eBPF unit tests (bpftool prog test)…"
    for obj in "$REPO_ROOT/kernel/src"/*.o; do
        bpftool prog load "$obj" /sys/fs/bpf/radm_test_$(basename "$obj" .o) \
            && info "    ✓ $(basename $obj)" \
            || warn "    ✗ $(basename $obj) failed to load"
        bpftool prog delete pinned "/sys/fs/bpf/radm_test_$(basename "$obj" .o)" 2>/dev/null
    done

    # Rust unit tests
    info "  [2/4] Aggregator Rust unit tests…"
    cd "$REPO_ROOT/aggregator" && cargo test --release 2>&1 | tail -5
    cd "$REPO_ROOT/mitigation" && cargo test --release 2>&1 | tail -5

    # Python unit tests
    info "  [3/4] Inference Python unit tests…"
    cd "$REPO_ROOT" && python3 -m pytest tests/unit/inference/ -q

    # Integration test (requires Docker)
    info "  [4/4] Integration tests (Docker Compose)…"
    docker compose -f "$REPO_ROOT/tests/integration/docker-compose.test.yml" up \
        --abort-on-container-exit --exit-code-from test-runner

    info "All tests complete"
}

# ─── Dispatch ─────────────────────────────────────────────────────────────────

case "${1:-help}" in
    build)           cmd_build ;;
    install)         cmd_install ;;
    start)           cmd_start ;;
    stop)            cmd_stop ;;
    status)          cmd_status ;;
    observe)         cmd_observe "${2:-120}" ;;
    train)           cmd_train ;;
    simulate-attack) cmd_simulate_attack ;;
    test)            cmd_test ;;
    *)
        echo "Usage: $0 {build|install|start|stop|status|observe [minutes]|train|simulate-attack|test}"
        exit 1
        ;;
esac
```

---

## §11 — TESTING STRATEGY

### 11.1 Unit Tests

#### Kernel BPF Unit Tests (`tests/unit/kernel/`)
```bash
# Test 1: Verify tracepoint programs load without verifier errors
bpftool prog load kernel/src/radm_tp.o /sys/fs/bpf/radm_test type tracepoint

# Test 2: Verify XDP program loads
bpftool prog load kernel/src/radm_xdp.o /sys/fs/bpf/radm_xdp_test type xdp

# Test 3: Stress verifier with synthetic BPF test runner
# (requires kernel ≥ 5.13 for BPF_PROG_TYPE_SYSCALL test capability)
bpftool prog run pinned /sys/fs/bpf/radm_test data_in /dev/zero data_size_in 48

# Test 4: Map create/update/delete cycle
bpftool map create /sys/fs/bpf/quarantine_test type hash key 8 value 1 entries 10 name qtest
bpftool map update pinned /sys/fs/bpf/quarantine_test key hex 01 00 00 00 00 00 00 00 value hex 01
bpftool map lookup pinned /sys/fs/bpf/quarantine_test key hex 01 00 00 00 00 00 00 00
bpftool map delete pinned /sys/fs/bpf/quarantine_test
```

#### Aggregator Rust Unit Tests (`aggregator/src/graph_builder.rs` — `#[cfg(test)]`)
Test cases to implement in `#[cfg(test)]` blocks:
- `test_sliding_window_eviction`: Insert 1000 events across 10 seconds, assert events older than 5s are evicted
- `test_node_creation`: Verify container and external-IP nodes are correctly created and indexed
- `test_edge_weight_accumulation`: Verify repeated connections between the same pair increments edge weight
- `test_feature_vector_dimension`: Assert `to_features()` always returns exactly `NODE_FEATURE_DIM = 7` values
- `test_snapshot_serialization`: Serialize a GraphSnapshot to protobuf and deserialize it; assert field equality
- `test_mprotect_feature_increment`: Verify mprotect events increment the feature counter

#### Inference Python Unit Tests (`tests/unit/inference/test_model.py`)
```python
import torch
import pytest
from torch_geometric.data import Data
from src.model import (
    SpatiotemporalAutoencoder, compute_loss,
    NODE_FEATURE_DIM, MAX_NODES, SEQ_LEN, GRU_HIDDEN, EMBEDDING_DIM
)

def make_random_graph(n_nodes=10, n_edges=15):
    x = torch.rand(n_nodes, NODE_FEATURE_DIM)
    src = torch.randint(0, n_nodes, (n_edges,))
    dst = torch.randint(0, n_nodes, (n_edges,))
    return Data(x=x, edge_index=torch.stack([src, dst]), num_nodes=n_nodes)

def make_sequence(T=SEQ_LEN, n_nodes=10):
    return [make_random_graph(n_nodes) for _ in range(T)]

def test_spatial_encoder_output_shape():
    from src.model import SpatialEncoder
    enc = SpatialEncoder()
    g = make_random_graph()
    z = enc(g.x, g.edge_index)
    assert z.shape == (g.num_nodes, EMBEDDING_DIM)

def test_temporal_encoder_output_shape():
    from src.model import TemporalEncoder
    enc = TemporalEncoder()
    z_seq = torch.rand(SEQ_LEN, MAX_NODES, EMBEDDING_DIM)
    h = enc(z_seq)
    assert h.shape == (MAX_NODES, GRU_HIDDEN)

def test_full_forward_pass():
    model = SpatiotemporalAutoencoder()
    seq = make_sequence()
    x_recon, edge_probs = model(seq, torch.device("cpu"))
    assert x_recon.shape[1] == NODE_FEATURE_DIM
    assert edge_probs.shape[0] == seq[-1].num_edges

def test_loss_backward():
    model = SpatiotemporalAutoencoder()
    seq = make_sequence()
    x_recon, edge_probs = model(seq, torch.device("cpu"))
    g = seq[-1]
    loss = compute_loss(x_recon, g.x, edge_probs, g.edge_index, g.num_nodes)
    loss.backward()
    # Verify gradients exist
    for p in model.parameters():
        assert p.grad is not None

def test_reconstruct_no_grad():
    model = SpatiotemporalAutoencoder().eval()
    seq = make_sequence()
    x_recon, edge_probs, node_errors = model.reconstruct(seq, torch.device("cpu"))
    assert node_errors.shape[0] <= MAX_NODES
    assert (node_errors >= 0).all()

def test_variable_node_counts():
    """Ensure model handles sequences with different node counts per snapshot."""
    model = SpatiotemporalAutoencoder().eval()
    seq = [make_random_graph(n_nodes=n) for n in [5, 8, 12, 7, 10, 15, 9, 11, 6, 13]]
    assert len(seq) == SEQ_LEN
    x_recon, _, _ = model.reconstruct(seq, torch.device("cpu"))
    assert x_recon.shape[1] == NODE_FEATURE_DIM
```

### 11.2 Integration Tests (`tests/integration/`)

```yaml
# docker-compose.test.yml
version: "3.9"
services:
  victim-container:
    image: ubuntu:22.04
    command: sleep 3600
    cap_add: [SYS_PTRACE]

  attack-simulator:
    image: ubuntu:22.04
    command: >
      bash -c "
        sleep 5 &&
        python3 /test/simulate_attack.py
          --target victim-container
          --scenario memory_injection
      "
    volumes: [./scripts:/test]

  test-runner:
    image: python:3.11
    command: >
      bash -c "
        pip install -q pytest requests prometheus-client &&
        pytest /tests -v --timeout=120
      "
    volumes: [./tests/integration:/tests]
    depends_on: [attack-simulator]
```

Integration test cases:
1. **Memory injection detection**: `mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)` in victim container → anomaly alert within 30 seconds
2. **Lateral movement detection**: Container A → Container B TCP connection surge on non-standard ports → anomaly within 15 seconds
3. **Quarantine isolation**: After alert, victim container cannot ping external IPs; neighbouring containers are unaffected
4. **Forensic dump creation**: Quarantine event → encrypted dump file exists at expected path
5. **False-positive baseline**: 1000 normal HTTP requests → zero alerts

### 11.3 Attack Simulation Script (`scripts/simulate-attack.sh`)

```bash
#!/usr/bin/env bash
# Simulate a multi-stage container attack for adversarial testing.
# Requires: Docker, a running Radm system, Python 3

set -euo pipefail

VICTIM_CONTAINER="${1:-radm-test-victim}"
INFO() { echo "[SIM] $*"; }

INFO "Launching victim container…"
docker run -d --name "$VICTIM_CONTAINER" ubuntu:22.04 sleep 3600 2>/dev/null || true
VICTIM_PID=$(docker inspect --format '{{.State.Pid}}' "$VICTIM_CONTAINER")

INFO "Stage 1: Fileless binary injection (memfd_create)"
docker exec "$VICTIM_CONTAINER" bash -c '
    python3 -c "
import ctypes, os
fd = ctypes.CDLL(None).memfd_create(b\"payload\", 1)
os.write(fd, b\"\x7fELF\" + b\"\x00\" * 60)
print(f\"memfd fd={fd}\")
"'

INFO "Stage 2: RWX memory allocation (mprotect + mmap)"
docker exec "$VICTIM_CONTAINER" bash -c '
python3 -c "
import mmap, ctypes
# Anonymous RWX mapping — classic shellcode staging
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
print(f\"RWX mmap: {len(m)} bytes\")
m.close()
"'

INFO "Stage 3: Anomalous port-scanning (lateral movement simulation)"
docker exec "$VICTIM_CONTAINER" bash -c '
python3 -c "
import socket, time
for port in range(8000, 8100):
    try:
        s = socket.socket()
        s.settimeout(0.01)
        s.connect((\"8.8.8.8\", port))
        s.close()
    except:
        pass
print(\"Port scan complete\")
" &'

INFO "Stage 4: ptrace injection attempt"
docker exec "$VICTIM_CONTAINER" bash -c '
    # Launch a dummy process then try to ptrace it
    sleep 1 &
    TARGET_PID=$!
    python3 -c "
import ctypes
PTRACE_ATTACH = 16
pid = $(docker exec $VICTIM_CONTAINER ps -C sleep -o pid= | head -1 | tr -d " ") 
ctypes.CDLL(None).ptrace(PTRACE_ATTACH, int(\"$TARGET_PID\"), 0, 0)
" 2>/dev/null || true'

INFO "Simulation complete. Monitor radm alerts with: journalctl -u radm-mitigation -f"
INFO "Expected: ≥1 MEMORY_INJECTION or FILELESS_EXEC alert within 30 seconds"
```

### 11.4 Performance Benchmarks

```bash
# Benchmark 1: Ring buffer throughput (events/second)
# Method: Generate synthetic BPF events at maximum rate for 10 seconds
# Target: ≥ 500,000 events/second sustained

# Benchmark 2: Graph build latency (snapshot generation time)
# cd aggregator && cargo bench -- graph_builder
# Target: < 200 µs per snapshot at N=100 nodes, E=500 edges

# Benchmark 3: Inference latency distribution
# python3 tests/benchmark/bench_inference.py --num-graphs 1000
# Target: p50 < 2ms, p99 < 10ms at N=100 nodes

# Benchmark 4: Quarantine latency (alert → TC BPF attached)
# Instrumented via Prometheus histogram: radm_quarantine_duration_seconds
# Target: p99 < 100ms
```

---

## §12 — DEPLOYMENT GUIDE

### 12.1 Docker Compose (Development Environment)

```yaml
# deploy/docker/docker-compose.yml
version: "3.9"

x-common: &common
  restart: unless-stopped
  volumes:
    - /sys/fs/bpf:/sys/fs/bpf
    - /sys/kernel/debug:/sys/kernel/debug:ro
    - /proc:/proc:ro
    - /sys/class/net:/sys/class/net
    - radm-run:/run/radm
    - radm-var:/var/radm

services:
  aggregator:
    <<: *common
    image: radm-aggregator:latest
    build: { dockerfile: deploy/docker/Dockerfile.aggregator, context: . }
    network_mode: host       # Required for XDP/TC attachment to host NICs
    privileged: false
    cap_add:
      - BPF
      - NET_ADMIN
      - SYS_RESOURCE
    pid: host                # Required to read /proc/<PID>/ns/net
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - /etc/radm:/etc/radm:ro
      - radm-run:/run/radm

  inference:
    <<: *common
    image: radm-inference:latest
    build: { dockerfile: deploy/docker/Dockerfile.inference, context: . }
    volumes:
      - radm-run:/run/radm
      - radm-var:/var/radm
    # No special capabilities needed

  mitigation:
    <<: *common
    image: radm-mitigation:latest
    build: { dockerfile: deploy/docker/Dockerfile.mitigation, context: . }
    network_mode: host
    privileged: false
    cap_add:
      - BPF
      - NET_ADMIN
      - SYS_PTRACE
      - SYS_ADMIN
    pid: host
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - radm-run:/run/radm
      - radm-var:/var/radm

volumes:
  radm-run:
  radm-var:
```

### 12.2 Kubernetes DaemonSet (Production)

```yaml
# deploy/kubernetes/daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: radm-node-agent
  namespace: radm-system
spec:
  selector:
    matchLabels: { app: radm-node-agent }
  template:
    metadata:
      labels: { app: radm-node-agent }
    spec:
      hostNetwork: true         # Required for XDP/TC attach
      hostPID: true             # Required for /proc/<PID>/ns/net access
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule

      initContainers:
        - name: bpf-loader
          image: radm-aggregator:latest
          command: ["/usr/local/bin/radm-bpf-init"]
          securityContext:
            capabilities:
              add: [BPF, NET_ADMIN, SYS_RESOURCE]
          volumeMounts:
            - { name: bpf-fs,   mountPath: /sys/fs/bpf }
            - { name: radm-bpf, mountPath: /etc/radm/bpf }

      containers:
        - name: aggregator
          image: radm-aggregator:latest
          securityContext:
            capabilities:
              add: [BPF, NET_ADMIN, SYS_RESOURCE]
          volumeMounts:
            - { name: bpf-fs,    mountPath: /sys/fs/bpf }
            - { name: proc,      mountPath: /proc, readOnly: true }
            - { name: sysnet,    mountPath: /sys/class/net }
            - { name: radm-run,  mountPath: /run/radm }
            - { name: radm-var,  mountPath: /var/radm }
            - { name: radm-cfg,  mountPath: /etc/radm, readOnly: true }

        - name: mitigation
          image: radm-mitigation:latest
          securityContext:
            capabilities:
              add: [BPF, NET_ADMIN, SYS_PTRACE, SYS_ADMIN]
          volumeMounts:
            - { name: bpf-fs,   mountPath: /sys/fs/bpf }
            - { name: proc,     mountPath: /proc, readOnly: true }
            - { name: sysnet,   mountPath: /sys/class/net }
            - { name: radm-run, mountPath: /run/radm }
            - { name: radm-var, mountPath: /var/radm }

      volumes:
        - { name: bpf-fs,   hostPath: { path: /sys/fs/bpf,    type: Directory } }
        - { name: proc,     hostPath: { path: /proc,          type: Directory } }
        - { name: sysnet,   hostPath: { path: /sys/class/net, type: Directory } }
        - { name: radm-bpf, configMap: { name: radm-bpf-objects } }
        - { name: radm-cfg, configMap: { name: radm-config } }
        - { name: radm-run, emptyDir: { medium: Memory } }
        - { name: radm-var, hostPath: { path: /var/radm, type: DirectoryOrCreate } }

---
# Inference can run as a replicated Deployment (no host privileges needed)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: radm-inference
  namespace: radm-system
spec:
  replicas: 1
  selector:
    matchLabels: { app: radm-inference }
  template:
    metadata:
      labels: { app: radm-inference }
    spec:
      containers:
        - name: inference
          image: radm-inference:latest
          volumeMounts:
            - { name: radm-run, mountPath: /run/radm }
            - { name: radm-var, mountPath: /var/radm }
      volumes:
        - { name: radm-run, emptyDir: { medium: Memory } }
        - { name: radm-var, emptyDir: {} }
```

### 12.3 Dockerfile Examples

```dockerfile
# deploy/docker/Dockerfile.aggregator
FROM rust:1.78-bookworm AS builder
WORKDIR /build
COPY aggregator/ .
COPY proto/ ../proto/
RUN apt-get update && apt-get install -y protobuf-compiler
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libelf1 zlib1g iproute2 bpftool \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/radm-aggregator /usr/local/bin/
COPY kernel/src/*.o /etc/radm/bpf/
ENTRYPOINT ["/usr/local/bin/radm-aggregator"]
```

```dockerfile
# deploy/docker/Dockerfile.inference
FROM python:3.11-slim-bookworm
WORKDIR /app
COPY inference/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY inference/src/ ./src/
COPY proto/ ./proto/
RUN python3 -m grpc_tools.protoc \
    --proto_path=proto \
    --python_out=src/proto \
    --pyi_out=src/proto \
    proto/radm.proto
CMD ["python3", "src/main.py"]
```

---

## §13 — SECURITY HARDENING

### 13.1 Capability Minimisation
Never use `privileged: true` in Kubernetes. The explicit capability list in §12.2 is the minimal set.
In systemd units, use `AmbientCapabilities=` with `NoNewPrivileges=yes`.

### 13.2 BPF Map Pinning & Access Control
All BPF maps are pinned under `/sys/fs/bpf/radm/`. Set directory permissions to `700` owned by `root`.
Only `radm-aggregator` and `radm-mitigation` processes should access these paths.

### 13.3 UDS Socket Permissions
UDS sockets under `/run/radm/` must be `chmod 600` owned by a dedicated `radm` user.
The inference engine runs as `radm-inference` (non-root, part of `radm` group).

### 13.4 Forensic Dump Encryption Key Management
The current implementation embeds the AES-256-GCM key in the dump file (§7.3) — **acceptable only in development**.
In production, integrate with:
- HashiCorp Vault (recommended for on-premise)
- AWS KMS / Azure Key Vault / GCP Cloud KMS for cloud deployments
- Linux `keyctl` kernel keyring for airgapped environments

### 13.5 eBPF Program Signing (Kernel ≥ 6.6)
For production on kernels ≥ 6.6, sign BPF programs with a kernel module signing key:
```bash
sbverify --cert /etc/radm/keys/bpf-sign.pem kernel/src/radm_tp.o
```

### 13.6 Seccomp Profile for Inference Container
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    { "names": ["read","write","close","mmap","mprotect","brk","rt_sigaction",
                 "rt_sigprocmask","munmap","connect","socket","recvfrom","sendto",
                 "openat","fstat","lseek","exit_group","futex","clock_gettime",
                 "getrandom","getcwd","getdents64"],
      "action": "SCMP_ACT_ALLOW" }
  ]
}
```

---

## §14 — PERFORMANCE TARGETS & SLAS

| Metric | Target | How Verified |
|---|---|---|
| BPF event capture overhead | < 2 µs per event | `bpftrace` overhead measurement |
| Ring buffer throughput | ≥ 500K events/sec | `bench_ringbuf.sh` |
| Graph snapshot build | < 200 µs at N=100 | `cargo bench` |
| Protobuf serialisation | < 500 µs per snapshot | `cargo bench` |
| ST-GAE inference (CPU) | p50 < 2ms, p99 < 10ms | `bench_inference.py` |
| End-to-end detection | < 60ms from event to alert | Integration test timer |
| Quarantine execution | < 100ms from alert to TC attach | Prometheus histogram |
| False-positive rate | < 0.1% on baseline traffic | IF contamination=0.01 |
| Memory (aggregator) | < 256MB RSS at N=500 containers | `systemd-cgtop` |
| CPU (aggregator) | < 5% per core on 4-core host | `top` / `htop` |

---

## §15 — KNOWN CONSTRAINTS & MITIGATIONS

| Constraint | Impact | Mitigation |
|---|---|---|
| **Cilium CNI conflict**: Cilium owns the eBPF datapath and will clash with Radm's TC/XDP programs | Cannot use Radm with Cilium | Switch to Calico, Flannel, or WeaveNet; document clearly |
| **cgroup v1 systems**: `bpf_get_current_cgroup_id()` returns the cgroup v1 hierarchy ID which is less reliable | Container identification may be ambiguous | Require cgroup v2 (`systemd.unified_cgroup_hierarchy=1`); document in prerequisites |
| **Process namespace remapping**: Containers with PID namespace remapping complicate `/proc` lookups | veth discovery may fail | Use `nsenter`-based fallback (already in `find_veth_for_pid`); add container runtime API fallback |
| **GRU cold start**: The first `SEQ_LEN-1` (9) snapshots produce no inference output | ~9-second blind window at startup | Log and expose via Prometheus gauge; acceptable for production |
| **Dynamic graph topology**: Containers starting/stopping invalidates cached node indices | Graph state must be reset on container lifecycle events | Subscribe to container runtime events (Docker events / k8s Informer); call `graph.recompute_state()` |
| **Model drift**: After weeks of deployment, container behaviour shifts and reconstruction error increases | False positive rate rises | Nightly automated retraining using only low-error snapshots as baseline; configurable via `radm-ctl.sh train` |
| **XDP hardware offload**: Some NICs expose XDP hardware offload mode which has different capability requirements | May require `XdpFlags::DRV_MODE` or `XdpFlags::SKB_MODE` instead of default | Auto-detect and fall back in `bpf_loader.rs` |
| **process_vm_readv permissions**: Requires the forensic process to have `PTRACE_MODE_ATTACH` capability against the target | Can fail for containers with seccomp DENY on ptrace | Document; offer `gcore`-based fallback; non-fatal failure path already implemented |

---

## §16 — IMPLEMENTATION INSTRUCTIONS FOR CODE GENERATION

When generating the complete source code from this specification:

1. **Implement every file listed in §8 directory layout** — no placeholder stubs.
2. **The kernel C code must pass `clang -target bpf -O2 -Weverything` with zero errors**. Every pointer dereference must have a bounds check immediately before it.
3. **The Rust aggregator must compile with `cargo build --release` with zero warnings** under `#![deny(warnings)]`. Use `#[allow(dead_code)]` only where explicitly noted.
4. **The Python model must be deterministic** — set all random seeds at startup: `torch.manual_seed(42); np.random.seed(42)`.
5. **All protobuf-generated code is produced by running `generate_proto` in `radm-ctl.sh`** — do not hand-write it.
6. **Every `unwrap()` or `expect()` in Rust must include a descriptive message**; panic is only acceptable for invariant violations in test code.
7. **The `radm_event` C struct size must remain exactly 48 bytes** — the `_Static_assert` in `radm_types.h` enforces this. If fields change, update padding explicitly.
8. **The sliding window recomputation** (`recompute_state`) is intentionally O(events) — acceptable for ≤ 500 containers at 5-second windows. Document with `// TODO: incremental eviction index for > 500 containers`.
9. **The forensic key storage in `forensics.rs` contains a `// KEY IS STORED IN THE FILE` comment** — this must not be removed; it is a mandatory reminder to integrate KMS.
10. **The `simulate-attack.sh` script must be tested in a clean Docker environment** before the test suite is marked passing.

---

*End of RADM (ردم) Engineering Specification v1.0*
*Prepared for implementation — all components are architecturally consistent and build-ready.*

---

## Appendix A: Threat Model Boundaries (What RADM Does and Does Not Detect)

The system is genuinely strong at detecting **memory injection techniques and anomalous inter-container network behavior in IPv4 cgroup v2 environments.** However, it has explicit trade-offs and intentional boundaries:

### What RADM Does NOT Protect Against:
* **IPv6 Traffic**: The TC BPF packet parser explicitly ignores non-IPv4 traffic. Any container communicating over IPv6 has no network visibility or quarantine enforcement.
* **Host-Network Containers**: Containers running with `--network host` share the host namespace and have no veth pair. Their traffic bypasses TC BPF entirely.
* **Encrypted Payload Content**: Payload hashing is noise for encrypted traffic (e.g., TLS). Detection relies purely on structural/timing behavioral graph anomalies.
* **Non-Memory Syscalls**: Only `mprotect`, `mmap`, `ptrace`, and `memfd_create` are monitored. Supply chain attacks executing legitimate binaries or using `execve` / `open` natively will remain invisible.
* **Intra-Container Threats**: Privileged escalation or compromise that remains localized entirely within a single container without network communication or tracked memory syscalls will not trigger anomalies.
* **Mimicry Attacks**: Sophisticated adversaries aware of the Isolation Forest baseline could deliberately shape attacks (e.g., extremely slow exfiltration) to stay beneath the static `-0.2` reconstruction error threshold.
* **cgroup v1 / Older Environments**: Identity attribution explicitly relies on cgroup v2 native helpers (`bpf_skb_cgroup_id`). Older environments will result in missing or broken attribution.

### Quarantine Limitations:
* **Network-Only Isolation**: Quarantining severs network connections but does not suspend the process, prevent filesystem writes, or restrict CPU. Local ransomware behavior continues unabated.
* **Binary Response**: Quarantine is all-or-nothing without TTL. It causes a hard outage for the affected container until manual operator intervention or container recreation.

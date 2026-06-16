<div align="center">

# ردم

**An efficient kernel-level IDS for multi-tenant containerised infrastructures**

For a complete description of what the system does and does not protect against, see the [full breakdown](RADM_SPEC.md).

---

*radm (Arabic: ردم) : means a massive, impenetrable barrier, dam, or wall.*
*A name that describes exactly what this system does to compromised containers.*

---

</div>

## Overview

**RADM** is a kernel-native intrusion detection system for containerised workloads. It uses eBPF to hook the Linux kernel — monitoring syscall and network activity across all containers with zero agent installation and zero container modification — and autonomously isolates compromised containers in under 160ms.

The system monitors memory manipulation primitives (`mprotect`, `mmap`, `ptrace`, `memfd_create`) and inter-container network flows, constructs a live temporal behavioral graph across all workloads, and detects intrusions at the host level rather than in isolation per-container.

## Runtime Modes

- **Linux (full dataplane)** — eBPF tracepoints, TC hooks, XDP, and Unix domain sockets fully active. Requires kernel 5.15+ with BTF/CO-RE and cgroup v2.
- **Non-Unix (mock mode)** — for local development and pipeline verification. Rust services start, emit synthetic events, and exercise the full pipeline logic without kernel attachment.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Kernel                             │
│                                                                 │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐                    │
│   │ radm_tp  │   │ radm_tc  │   │ radm_xdp │                    │
│   │ Syscall  │   │ Network  │   │ DDoS     │                    │
│   │ Probes   │   │ Monitor  │   │ Gate     │                    │
│   └────┬─────┘   └────┬─────┘   └──────────┘                    │
│        │              │                                         │
│        └──────┬───────┘                                         │
│               ▼                                                 │
│        ┌─────────────┐      ┌────────────────┐                  │
│        │ Ring Buffer │      │ quarantine_map │                  │
│        │   (16 MB)   │      │  (BPF Hash)    │                  │
│        └──────┬──────┘      └───────▲────────┘                  │
└───────────────┼──────────────────────┼──────────────────────────┘
                │                      │
        ════════╪══════════════════════╪════════  User / Kernel
                ▼                      │
┌───────────────────────────┐          │
│   Aggregator (Rust)       │          │
│                           │          │
│   Ring Buffer Consumer    │          │
│   Sliding-Window Graph    │          │
│   Protobuf Serialization  │          │
│   UDS Server              │          │
└────────────┬──────────────┘          │
             │  GraphSnapshot          │
             ▼                         │
┌───────────────────────────┐          │
│   Inference (Python)      │          │
│                           │          │
│   ST-GAE Encoder/Decoder  │          │
│   GRU Temporal Layer      │          │
│   Isolation Forest        │          │
│   Threat Classification   │          │
└────────────┬──────────────┘          │
             │  AnomalyAlert           │
             ▼                         │
┌───────────────────────────┐          │
│   Mitigation (Rust)       │──────────┘
│                           │  Updates quarantine_map
│   TC Filter Quarantine    │
│   Forensic Memory Dump    │
│   AES-GCM Encryption      │
└───────────────────────────┘
```

## Project Structure

```
ردم/
├── kernel/                  # eBPF programs (C)
│   └── src/
│       ├── radm_tp.c        # Syscall tracepoint monitors
│       ├── radm_tc.c        # TC network monitor + quarantine enforcement
│       ├── radm_xdp.c       # XDP early packet drop (DDoS gate)
│       ├── radm_types.h     # Shared event struct (48 bytes, static-asserted)
│       ├── radm_maps.h      # BPF map declarations
│       └── radm_helpers.h   # Rate limiter, hash, event emission
│
├── aggregator/              # Ring buffer consumer + graph builder (Rust)
│   └── src/
│       ├── main.rs          # Entry point, async runtime
│       ├── ring_reader.rs   # BPF ring buffer consumer via aya
│       ├── graph_builder.rs # 5-second sliding-window graph construction
│       ├── uds_server.rs    # Unix Domain Socket server for inference
│       ├── cgroup_resolver.rs # cgroup_id → container name resolution
│       ├── config.rs        # Configuration schema
│       └── types.rs         # Rust-side event types
│
├── inference/               # Detection engine (Python)
│   └── src/
│       ├── main.py          # Entry point
│       ├── model.py         # ST-GAE: GATv2 encoder + GRU temporal + decoder
│       ├── trainer.py       # Offline training pipeline
│       └── detector.py      # Online detection loop
│
├── mitigation/              # Quarantine + forensics (Rust)
│   └── src/
│       ├── main.rs          # Entry point
│       ├── control.rs       # Alert consumer, quarantine orchestration
│       ├── quarantine.rs    # TC filter attachment, BPF map updates
│       └── forensics.rs     # AES-GCM encrypted memory dump
│
├── proto/
│   └── radm.proto           # Protobuf schema (all IPC messages)
│
├── scripts/
│   ├── radm-ctl.sh          # Lifecycle manager (start/stop/status)
│   └── simulate-attack.sh   # Multi-stage attack simulator
│
├── config/
│   └── radm.toml            # Runtime configuration
│
├── tests/
│   ├── unit/
│   │   └── inference/
│   │       └── test_model.py
│   └── integration/
│       └── docker-compose.test.yml
│
├── Makefile                 # Build orchestration
└── RADM_SPEC.md             # Full engineering specification (v1.0)
```

## Core Pipeline

1. **Kernel** — Syscall tracepoints fire on `mprotect`, `mmap`, `ptrace`, and `memfd_create`, emitting 48-byte `radm_event` structs into a 16MB lockless BPF ring buffer. TC hooks on container veth pairs capture network metadata and enforce quarantine via `TC_ACT_SHOT`. XDP gates the host NIC for early DDoS-level drops.

2. **Aggregator** — The Rust aggregator consumes events from the ring buffer, resolves `cgroup_id` to container identity via `/proc`, and maintains a 5-second sliding-window behavioral graph. Snapshots are serialized as Protobuf and streamed to the inference engine over a Unix Domain Socket.

3. **Inference** — The Python engine receives `GraphSnapshot` protobufs, runs them through a Spatiotemporal Graph Autoencoder (GATv2 spatial encoder + GRU temporal layer), computes per-node reconstruction error, and classifies intrusions via Isolation Forest. Alerts are emitted as `AnomalyAlert` protobufs.

4. **Mitigation** — The Rust mitigation plane receives alerts, attaches TC BPF filters to the target container's veth pair, updates the `quarantine_map` to drop all traffic, and optionally performs AES-GCM encrypted forensic memory dumps.

## Requirements

### Linux (full dataplane)

- Linux kernel >= 5.15 (BTF/CO-RE, cgroup v2)
- `clang` >= 15, `bpftool`, `tc`, `ip`
- Rust >= 1.70 (`rustc`, `cargo`)
- Python >= 3.10 with PyTorch >= 2.0 and PyTorch Geometric
- `protoc` (Protocol Buffers compiler)
- Container runtime with veth-based networking

### Local development (non-Unix)

- Rust toolchain
- Python 3.12
- `numpy`, `protobuf`, `pyyaml`, `scikit-learn`, `pytest`

The repo includes lightweight inference compatibility shims so tests run on constrained hosts without a full PyTorch installation.

## Building

```bash
# Full build (eBPF + Rust + Protobuf bindings)
make all

# Rust components only
cargo build --manifest-path aggregator/Cargo.toml
cargo build --manifest-path mitigation/Cargo.toml

# Python unit tests
python -m pytest tests/unit/inference -q
```

## Usage

```bash
# Start the full pipeline
sudo ./scripts/radm-ctl.sh start

# Check status
sudo ./scripts/radm-ctl.sh status

# Run the attack simulator (requires Docker)
sudo ./scripts/simulate-attack.sh

# Stop the pipeline
sudo ./scripts/radm-ctl.sh stop
```

On non-Unix hosts the Rust services start automatically in mock mode — the aggregator emits synthetic snapshots and the mitigation plane exercises the quarantine flow without kernel attachment.

## Configuration

- `radm.toml` — runtime configuration used by all services
- `config/radm.default.toml` — packaged defaults
- `proto/radm.proto` — source of truth for all IPC message schemas
- `/var/radm` — expected location for inference checkpoint and baseline data in production

## Threat Model

RADM is designed to detect **memory injection techniques and anomalous inter-container network behavior in IPv4 cgroup v2 environments**. For a full breakdown of what the system detects, what it explicitly does not protect against, and known trade-offs, see [RADM_SPEC.md](RADM_SPEC.md).

## Notes

- Cilium is not supported — it owns the eBPF datapath and conflicts with RADM's TC hooks.
- The full dataplane requires a Linux host. Windows/macOS development uses mock mode only.

## License

MIT License.

<div align="center">

# ردم

**Enterprise-Grade Hybrid Zero-Trust Container Security Engine**

---

*radm (Arabic: ردم) — to fill, to bury, to seal off.*
*A name that describes exactly what this system does to compromised containers.*

---

</div>

## Overview

**ردم** is a kernel-to-userspace container security engine that detects and autonomously quarantines compromised containers in real time. It combines eBPF-based syscall and network telemetry with a Spatiotemporal Graph Autoencoder (ST-GAE) for behavioral anomaly detection, achieving sub-160ms detection-to-quarantine latency.

The system monitors memory manipulation primitives (`mprotect`, `mmap`, `ptrace`, `memfd_create`) and inter-container network flows, constructs a temporal behavioral graph, and uses learned baselines to identify deviations indicative of container compromise.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Kernel                             │
│                                                                 │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐                   │
│   │ radm_tp  │   │ radm_tc  │   │ radm_xdp │                   │
│   │ Syscall  │   │ Network  │   │ DDoS     │                   │
│   │ Probes   │   │ Monitor  │   │ Gate     │                   │
│   └────┬─────┘   └────┬─────┘   └──────────┘                   │
│        │              │                                         │
│        └──────┬───────┘                                         │
│               ▼                                                 │
│        ┌─────────────┐      ┌────────────────┐                  │
│        │  Ring Buffer │      │ quarantine_map │                  │
│        │   (16 MB)    │      │  (BPF Hash)    │                  │
│        └──────┬───────┘      └───────▲────────┘                  │
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
│   AES-GCM Encryption     │
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
├── inference/               # Anomaly detection engine (Python)
│   └── src/
│       ├── main.py          # Entry point
│       ├── model.py         # ST-GAE: GATv2 encoder + GRU temporal + decoder
│       ├── trainer.py       # Offline training pipeline
│       └── detector.py      # Online anomaly detection loop
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

The v1 core loop implements the following end-to-end data flow:

1. **Kernel**: Syscall tracepoints (`mprotect`, `mmap`, `ptrace`, `memfd_create`) fire and emit 48-byte `radm_event` structs into a 16MB BPF ring buffer. TC hooks on container veth pairs capture network metadata and enforce quarantine via `TC_ACT_SHOT`.

2. **Aggregator**: The Rust aggregator consumes events from the ring buffer, resolves `cgroup_id` to container identity via `/proc`, and maintains a 5-second sliding-window behavioral graph. Graph snapshots are serialized as Protobuf and streamed to the inference engine over a Unix Domain Socket.

3. **Inference**: The Python inference engine receives `GraphSnapshot` protobufs, feeds them through a Spatiotemporal Graph Autoencoder (GATv2 spatial encoder, GRU temporal layer), computes per-node reconstruction error, and classifies anomalies using an Isolation Forest. Alerts are emitted as `AnomalyAlert` protobufs.

4. **Mitigation**: The Rust mitigation plane receives alerts, attaches TC BPF filters to the target container's veth pair, updates the `quarantine_map` to drop all traffic, and optionally performs AES-GCM encrypted forensic memory dumps.

## Requirements

- **Linux kernel** >= 5.15 (BTF/CO-RE support, cgroup v2)
- **clang** >= 15 (eBPF compilation)
- **Rust** >= 1.70 (aggregator and mitigation)
- **Python** >= 3.10 with PyTorch >= 2.0 and PyTorch Geometric (inference)
- **protoc** (Protocol Buffers compiler)

## Building

```bash
make all
```

This compiles the eBPF programs, builds the Rust components, and generates Protobuf bindings.

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

## Threat Model

The system is designed to detect **memory injection techniques and anomalous inter-container network behavior in IPv4 cgroup v2 environments**. For a complete description of what the system does and does not protect against, see [Appendix A of the specification](RADM_SPEC.md).

## License

All rights reserved.

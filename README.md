# RADM

RADM is a hybrid container security engine that combines kernel telemetry, behavioral graph construction, machine-learning based anomaly detection, and quarantine response. The implementation follows the engineering specification in `RADM_SPEC.md` and focuses on low-latency detection of memory-injection and suspicious network behavior in Linux container environments.

## Overview

The system is split into three primary planes:

- `aggregator`: loads telemetry, builds the sliding-window graph, and serves graph snapshots to inference.
- `inference`: consumes graph snapshots, scores behavior with the spatiotemporal autoencoder, and emits alerts.
- `mitigation`: receives alerts, applies quarantine actions, and records forensic output.

The kernel dataplane uses eBPF tracepoints, TC hooks, and XDP for telemetry and enforcement. The userspace pipeline exchanges Protobuf messages over Unix domain sockets.

## Runtime Modes

- Linux hosts: full dataplane mode with eBPF, TC, XDP, and Unix domain sockets.
- Non-Unix hosts: mock mode for local development and verification. The Rust services still start, emit synthetic events, and exercise the pipeline logic without kernel attachment.

## Repository Layout

- `kernel/`: eBPF C sources and kernel-side maps/helpers.
- `aggregator/`: Rust event consumer and graph builder.
- `inference/`: Python detection pipeline, training code, and compatibility shims for local testing.
- `mitigation/`: Rust quarantine and forensic capture logic.
- `proto/`: source schema for all IPC messages.
- `scripts/`: build, lifecycle, and attack-simulation helpers.
- `tests/`: unit and integration tests.
- `config/` and `radm.toml`: runtime configuration.

## Prerequisites

### Linux runtime

- Linux 5.15 or newer
- `clang`, `bpftool`, `rustc`, `cargo`, `protoc`, `tc`, and `ip`
- cgroup v2 and BTF enabled
- Container runtime support for veth-based networking

### Local development

- Rust toolchain
- Python 3.12
- MSYS packages for `numpy`, `protobuf`, `pyyaml`, `scikit-learn`, and `pytest`

The repository also includes lightweight local compatibility layers so the inference tests can run on constrained hosts without a full PyTorch installation.

## Build

```bash
cargo build --manifest-path aggregator/Cargo.toml
cargo build --manifest-path mitigation/Cargo.toml
```

To run the Python unit tests:

```bash
python -m pytest tests/unit/inference -q
```

On a Linux host with the required toolchain, the kernel objects can be built from `kernel/` with `make`.

## Run

### Linux

```bash
sudo ./scripts/radm-ctl.sh start
```

Useful companion commands:

```bash
sudo ./scripts/radm-ctl.sh status
sudo ./scripts/radm-ctl.sh stop
./scripts/simulate-attack.sh
```

### Non-Unix development hosts

The Rust services start in mock mode:

- `aggregator` emits synthetic snapshots and logs them.
- `mitigation` loads a mock alert and exercises the quarantine flow.

This is intentional and lets the codebase be validated without Linux kernel features.

## Validation Performed

- `cargo build` for `aggregator`
- `cargo build` for `mitigation`
- `python -m pytest tests/unit/inference -q`
- Runtime smoke tests for the aggregator and mitigation mock modes

## Configuration

- `radm.toml` is the runtime configuration used by the services.
- `config/radm.default.toml` is the packaged default config.
- `proto/radm.proto` is the source of truth for all IPC messages.

## Notes

- The full eBPF dataplane still requires a Linux host with the prerequisites above.
- Cilium is not supported because it owns the eBPF datapath.
- The inference checkpoint and baseline data are expected under `/var/radm` in production.


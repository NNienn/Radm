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

    for cmd in clang-15 bpftool rustc cargo python3 tc ip; do
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
    info "Protobuf bindings are checked in; no generation needed."
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
    REPO_ROOT="$REPO_ROOT" VAR_DIR="$VAR_DIR" RUN_DIR="$RUN_DIR" TIMEOUT_MINUTES="$minutes" python3 - <<'PYEOF'
import asyncio
import pathlib
import pickle
import struct
import time
import os
import sys

repo_root = pathlib.Path(os.environ["REPO_ROOT"])
sys.path.insert(0, str(repo_root / "inference" / "src"))

from proto import radm_pb2 as pb
from detector import proto_to_pyg

baseline_dir = pathlib.Path(os.environ["VAR_DIR"]) / "baseline"
baseline_dir.mkdir(parents=True, exist_ok=True)
timeout_seconds = int(os.environ["TIMEOUT_MINUTES"]) * 60
graph_socket = pathlib.Path(os.environ["RUN_DIR"]) / "graph.sock"


async def collect():
    reader, _ = await asyncio.open_unix_connection(str(graph_socket))
    sequence = 0
    start = time.time()
    while time.time() - start < timeout_seconds:
        header = await reader.readexactly(4)
        length = struct.unpack(">I", header)[0]
        raw = await reader.readexactly(length)
        snapshot = pb.GraphSnapshot()
        snapshot.ParseFromString(raw)
        graph = proto_to_pyg(snapshot)
        output = baseline_dir / f"snapshot_{sequence:08d}.pkl"
        output.write_bytes(pickle.dumps(graph))
        sequence += 1
        if sequence % 100 == 0:
            elapsed = time.time() - start
            print(f"  Collected {sequence} snapshots ({elapsed:.0f}s / {timeout_seconds}s)")


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

#!/usr/bin/env bash
set -euo pipefail

VICTIM_CONTAINER="${1:-radm-test-victim}"
IMAGE="${2:-python:3.11-slim}"

info() {
    echo "[SIM] $*"
}

cleanup() {
    docker rm -f "$VICTIM_CONTAINER" >/dev/null 2>&1 || true
}

trap cleanup EXIT

info "Launching victim container from $IMAGE"
docker run -d --name "$VICTIM_CONTAINER" "$IMAGE" sleep 3600 >/dev/null

info "Stage 1: memfd_create"
docker exec "$VICTIM_CONTAINER" python - <<'PY'
import ctypes
import os

libc = ctypes.CDLL(None)
fd = libc.memfd_create(b"payload", 1)
os.write(fd, b"\x7fELF" + b"\x00" * 60)
print(f"memfd fd={fd}")
PY

info "Stage 2: RWX mmap"
docker exec "$VICTIM_CONTAINER" python - <<'PY'
import mmap

region = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
print(f"RWX mmap bytes={len(region)}")
region.close()
PY

info "Stage 3: port scan simulation"
docker exec "$VICTIM_CONTAINER" python - <<'PY'
import socket

for port in range(8000, 8020):
    try:
        with socket.create_connection(("8.8.8.8", port), timeout=0.01):
            pass
    except OSError:
        pass
print("Port scan complete")
PY

info "Stage 4: ptrace attach attempt"
docker exec "$VICTIM_CONTAINER" python - <<'PY'
import ctypes
import os
import subprocess

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
libc = ctypes.CDLL(None)

proc = subprocess.Popen(["sleep", "1"])
try:
    libc.ptrace(PTRACE_ATTACH, proc.pid, None, None)
    os.waitpid(proc.pid, 0)
    libc.ptrace(PTRACE_DETACH, proc.pid, None, None)
    print(f"ptrace attached to pid={proc.pid}")
except OSError as exc:
    print(f"ptrace failed: {exc}")
PY

info "Simulation complete"
info "Monitor alerts with the mitigation service logs or the alert socket"

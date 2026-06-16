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

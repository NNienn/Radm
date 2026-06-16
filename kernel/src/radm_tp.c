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
    if (!(prot & 0x4)) /* PROT_EXEC = 0x4 */
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
    if (!(prot & 0x4) || !(flags & 0x20))
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

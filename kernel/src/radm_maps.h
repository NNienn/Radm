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

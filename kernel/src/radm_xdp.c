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

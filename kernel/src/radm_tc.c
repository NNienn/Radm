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
    void **payload_start,
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
    __u32 avail = (data_end > *payload_start)
                  ? (data_end - *payload_start) : 0;
    *payload_len = avail < 32 ? avail : 32;
    return 0;
}

static __always_inline int tc_handler(struct __sk_buff *skb, __u8 direction) {
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8  ip_proto = 0;
    void *payload  = NULL;
    __u32 plen     = 0;

    if (parse_packet(skb, &src_ip, &dst_ip, &src_port, &dst_port,
                     &ip_proto, &payload, &plen) < 0)
        return TC_ACT_OK;  /* Non-IP: pass through unchanged */

    /* Resolve cgroup_id for this packet's socket.
     * Use native kernel helper for network egress. */
    __u32 pid = 0; // Unused for network events
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

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
        if (payload + 32 <= data_end)
            ev.payload_hash = radm_hash32((const __u8 *)payload);
    }

    radm_emit_event(&ev);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int radm_tc_ingress(struct __sk_buff *skb) { return tc_handler(skb, 0); }

SEC("tc/egress")
int radm_tc_egress(struct __sk_buff *skb)  { return tc_handler(skb, 1); }

char LICENSE[] SEC("license") = "GPL";

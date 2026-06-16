/* radm_helpers.h */
#pragma once
#include "radm_maps.h"

/* Token-bucket rate limiter. Returns 1 if event should be passed, 0 if dropped. */
static __always_inline int radm_ratelimit_check(void) {
    __u32 key = 0;
    struct radm_ratelimit_state *state = bpf_map_lookup_elem(&ratelimit_map, &key);
    if (!state)
        return 1;  /* fail open — do not drop if state missing */

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ms = (now - state->last_refill_ns) / 1000000ULL;

    if (elapsed_ms > 0) {
        __u64 new_tokens = elapsed_ms * RADM_RATELIMIT_REFILL;
        state->tokens += new_tokens;
        if (state->tokens > RADM_RATELIMIT_CAPACITY)
            state->tokens = RADM_RATELIMIT_CAPACITY;
        state->last_refill_ns = now;
    }

    if (state->tokens == 0)
        return 0;  /* drop — bucket empty */

    state->tokens--;
    return 1;
}

/* BPF-safe MurmurHash3 over exactly 32 bytes (fully unrolled for verifier) */
#define RADM_HASH_SEED 0xdeadbeefU

static __always_inline __u32 radm_hash32(const __u8 *data) {
    __u32 h = RADM_HASH_SEED ^ 32U;
    __u32 k;

    /* 8 rounds × 4 bytes = 32 bytes, loop fully unrolled */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        __builtin_memcpy(&k, data + i * 4, 4);
        k *= 0xcc9e2d51u;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5u + 0xe6546b64u;
    }
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

/* Emit an event to the ring buffer; handles rate limiting and drop counting */
static __always_inline void radm_emit_event(struct radm_event *ev) {
    if (!radm_ratelimit_check()) {
        __u32 key = 0;
        __u64 *dc = bpf_map_lookup_elem(&drop_counter, &key);
        if (dc)
            __sync_fetch_and_add(dc, 1);
        return;
    }

    struct radm_event *slot = bpf_ringbuf_reserve(&telemetry_ring, sizeof(*ev), 0);
    if (!slot) {
        /* Ring buffer full despite rate limiting — increment drop counter */
        __u32 key = 0;
        __u64 *dc = bpf_map_lookup_elem(&drop_counter, &key);
        if (dc)
            __sync_fetch_and_add(dc, 1);
        return;
    }
    __builtin_memcpy(slot, ev, sizeof(*ev));
    bpf_ringbuf_submit(slot, 0);
}

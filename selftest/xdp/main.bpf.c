//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
long ringbuffer_flags = 0;

SEC("xdp")
int target(struct xdp_md *ctx) {
    int *process;

    // Reserve space on the ringbuffer for the sample
    process = bpf_ringbuf_reserve(&events, sizeof(int), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    *process = 2021;

    bpf_ringbuf_submit(process, ringbuffer_flags);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

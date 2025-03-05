//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

SEC("usdt/test_marker")
int usdt__test_marker(struct pt_regs *ctx)
{
    long *value;

    // Reserve space on the ringbuffer for the sample
    value = bpf_ringbuf_reserve(&events, sizeof(*value), ringbuffer_flags);
    if (!value) {
        return 0;
    }

    if (bpf_usdt_arg(ctx, 0, value) < 0) {
        bpf_ringbuf_discard(value, ringbuffer_flags);
        return 0;
    }

    bpf_ringbuf_submit(value, ringbuffer_flags);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

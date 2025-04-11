//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event_t {
    __u64 cookie;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

SEC("uprobe/test_functions")
int uprobe__test_functions(struct pt_regs *ctx)
{
    __u64 cookie = bpf_get_attach_cookie(ctx);

    bpf_printk("handle user function with cookie %llu\n", cookie);

    // Reserve space on the ringbuffer for the sample
    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), ringbuffer_flags);
    if (!event) {
        bpf_printk("error submitting event to ring buffer for user function with cookie %llu\n",
                   cookie);
        return 0;
    }

    // Send back to userspace the function name
    event->cookie = cookie;
    bpf_ringbuf_submit(event, ringbuffer_flags);
    return 0;
}
char __license[] SEC("license") = "GPL";

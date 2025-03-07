//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct dispatched_ctx {
    u64 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 4096 * sizeof(struct dispatched_ctx));
} dispatched SEC(".maps");

static long handle_dispatched_evt(struct bpf_dynptr *dynptr, void *context)
{
    const struct dispatched_ctx *ctx;

    ctx = bpf_dynptr_data(dynptr, 0, sizeof(*ctx));
    if (!ctx)
        return 0;

    if (ctx->id != 999) {
        return 1;
    }

    return 0;
}

SEC("syscall")
int test_user_ring_buff(struct dispatched_ctx *input)
{
    int errno;
    errno = bpf_user_ringbuf_drain(&dispatched, handle_dispatched_evt, NULL, 0);
    return errno;
}
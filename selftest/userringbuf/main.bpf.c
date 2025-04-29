//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct dispatched_ctx {
    u64 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 3 * sizeof(struct dispatched_ctx));
} dispatched SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256);
} errEvt SEC(".maps");

long ringbuffer_flags = 0;

static long handle_dispatched_evt(struct bpf_dynptr *dynptr, void *context)
{
    const struct dispatched_ctx *ctx;

    ctx = bpf_dynptr_data(dynptr, 0, sizeof(*ctx));
    if (!ctx)
        return 0;

    if (ctx->id != 999) {
        u64 *id = bpf_ringbuf_reserve(&errEvt, sizeof(u64), ringbuffer_flags);
        if (!id) {
            return 1;
        }
        bpf_ringbuf_submit(id, ringbuffer_flags);
        return 1;
    }

    return 0;
}

SEC("syscall")
int test_user_ring_buff(struct dispatched_ctx *input)
{
    int retVal;
    retVal = bpf_user_ringbuf_drain(&dispatched, handle_dispatched_evt, NULL, 0);
    return retVal;
}
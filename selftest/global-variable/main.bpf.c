//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct config_t {
    u64 a;
    char c[6];
};

struct event_t {
    u64 sum;
    char c[6];
};

const volatile u32 abc = 1;
const volatile u32 efg = 2;
const volatile struct config_t foobar = {};
const volatile long foo = 3;
volatile int bar = 4;
const volatile int baz SEC(".rodata.baz") = 5;
const volatile int qux SEC(".data.qux") = 6;

long ringbuffer_flags = 0;

SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    struct event_t *event;
    int i;

    // Reserve space on the ringbuffer for the sample
    event = bpf_ringbuf_reserve(&events, sizeof(*event), ringbuffer_flags);
    if (!event) {
        return 1;
    }

    event->sum = abc + efg + foobar.a + foo + bar + baz + qux;
    for (i = 0; i < sizeof(foobar.c); i++) {
        event->c[i] = foobar.c[i];
    }

    bpf_ringbuf_submit(event, ringbuffer_flags);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";

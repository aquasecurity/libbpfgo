//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define VAR_NUM 16

struct hmap_elem {
    struct bpf_spin_lock lock;
    int val;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hmap_elem);
} counter_hash_map SEC(".maps");

long ringbuffer_flags = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_mmap")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_mmap")
#endif
int mmap_fentry(struct pt_regs *ctx)
{
    int *process;
    struct hmap_elem *lost_event_counter;
    int key = 1;

    lost_event_counter = bpf_map_lookup_elem(&counter_hash_map, &key);
    if (!lost_event_counter) {
        return 0;
    }

    // Reserve space on the ringbuffer for the sample
    process = bpf_ringbuf_reserve(&events, sizeof(int), ringbuffer_flags);
    if (!process) {
        bpf_spin_lock(&lost_event_counter->lock);
        lost_event_counter->val++;
        bpf_spin_unlock(&lost_event_counter->lock);
        return 0;
    }

    *process = 2021;

    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";

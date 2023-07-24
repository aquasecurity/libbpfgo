//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_hash SEC(".maps");

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_mmap")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_mmap")
#endif
int mmap_fentry(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u8 *value = bpf_map_lookup_elem(&percpu_hash, &key);
    if (value) {
        *value += 1;
        bpf_printk("%d", *value);
        return 0;
    }

    bpf_printk("nothing");

    return 0;
}
char LICENSE[] SEC("license") = "GPL";

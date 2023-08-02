//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} one SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} two SEC(".maps");

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_mmap")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_mmap")
#endif
int mmap_fentry(struct pt_regs *ctx)
{
    return 0;
}

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_execve")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_execve")
#endif
int execve_fentry(struct pt_regs *ctx)
{
    return 0;
}

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_execveat")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_execveat")
#endif
int execveat_fentry(struct pt_regs *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

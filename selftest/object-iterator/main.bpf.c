//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

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

SEC("fentry/__x64_sys_mmap")
int mmap_fentry(struct pt_regs *ctx)
{
    return 0;
}

SEC("fentry/__x64_sys_execve")
int execve_fentry(struct pt_regs *ctx)
{
    return 0;
}

SEC("fentry/__x64_sys_execveat")
int execveat_fentry(struct pt_regs *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

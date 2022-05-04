//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

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

//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

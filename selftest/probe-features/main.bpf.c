//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    bpf_printk("Yankees will win the 2022 world series");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

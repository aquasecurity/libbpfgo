//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    bpf_printk("Hello, World!\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

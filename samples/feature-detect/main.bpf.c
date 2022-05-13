//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

// program type / event name / feature / ... / ...

SEC("fentry/__x64_sys_mmap")
int BPF_PROG(mmap_fentry)
{
    int i;
    for(i = 0; i < 5; i++) {
        bpf_printk("hello!");
    }
    return 0;
}

SEC("kprobe/__x64_sys_mmap")
int BPF_PROG(mmap_kprobe)
{
    bpf_printk("Yo!");
    return 0;
}


// SEC("execve/kprobe")
// int BPF_PROG(baz)
// {
//     bpf_printk("Hey!");
//     return 0;
// }

// char LICENSE[] SEC("license") = "GPL";

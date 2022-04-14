//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

SEC("fentry/commit_creds")
int BPF_PROG(commit_creds, struct cred *foobar)
{
    bpf_printk("%d", foobar->uid.val);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "map.bpf.h"

// Large instruction count
SEC("fentry/__x64_sys_openat")
int openat_fentry(struct pt_regs* ctx)
{
    bpf_printk("openat (multiple objects-1)");
    int* value;

    value = bpf_ringbuf_reserve(&events, sizeof(int), 0);
    if (!value) {
        return 0;
    }
    *value = 1;
    bpf_ringbuf_submit(value, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

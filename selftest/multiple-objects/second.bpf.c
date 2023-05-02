//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "map.bpf.h"

// Large instruction count
SEC("fentry/__x64_sys_mmap")
int mmap_fentry(struct pt_regs* ctx)
{
    bpf_printk("Mmap (multiple objects-2)");
    int* value;
    value = bpf_ringbuf_reserve(&events, sizeof(int), 0);
    if (!value) {
        return 0;
    }
    *value = 2;
    bpf_ringbuf_submit(value, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

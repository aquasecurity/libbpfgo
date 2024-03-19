//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef __TARGET_ARCH_amd64
SEC("fentry/__x64_sys_mmap")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_mmap")
#endif
int sys_mmap(struct pt_regs *ctx)
{
    return 0;
}

SEC("kprobe/do_sys_open")
int kprobe__sys_open(struct pt_regs *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

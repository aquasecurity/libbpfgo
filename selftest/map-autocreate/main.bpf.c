//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, ~0U);
} tester SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

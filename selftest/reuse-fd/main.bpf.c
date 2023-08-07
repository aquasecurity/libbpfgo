//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "main.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct value);
    __uint(max_entries, 1 << 4);
} tester SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct value);
    __uint(max_entries, 1 << 4);
} tester_reused SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

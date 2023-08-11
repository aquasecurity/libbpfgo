//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

// Hash map of maps with no inner maps preallocated.
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} outer_hash SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

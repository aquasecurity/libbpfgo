//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} inner_hash_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, typeof(inner_hash_0));
} outer_hash_0 SEC(".maps") = {
    .values =
        {
            &inner_hash_0,
        },
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} outer_hash_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} outer_array_2 SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} inner_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, typeof(inner_array));
} outer_hash SEC(".maps") = {
    .values =
        {
            [1917] = &inner_array,
        },
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

// https://lore.kernel.org/bpf/20200429002739.48006-4-andriin@fb.com/

struct inner_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} inner_map1 SEC(".maps"), inner_map2 SEC(".maps");

struct outer_hash {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 5);
    __uint(key_size, sizeof(__u32));
    __array(values, struct inner_map);
} outer_hash SEC(".maps") = {
    .values =
        {
            [0] = &inner_map2,
            [4] = &inner_map1,
        },
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

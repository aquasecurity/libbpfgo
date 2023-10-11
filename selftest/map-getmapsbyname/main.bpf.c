//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} test_name SEC(".maps");

// Define a struct to hold path and method
struct test_struct {
    char value[10];
};

// Define the eBPF map to store the path-method pairs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct test_struct);
} test_hash_name SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

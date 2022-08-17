//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} outer_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} outer_array SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

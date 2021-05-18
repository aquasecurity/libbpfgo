//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(max_entries, 5);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
} numbers SEC(".maps");
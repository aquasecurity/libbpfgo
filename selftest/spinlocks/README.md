# Spinlocks

https://lwn.net/Articles/776909/

In BTF annotated BPF maps, we can use a bpf_spin_lock to allow for atomic reads/updates of values in BPF maps.

It is NOT supported in programs of type:

- BPF_PROG_TYPE_KPROBE
- BPF_PROG_TYPE_TRACEPOINT
- BPF_PROG_TYPE_PERF_EVENT
- BPF_PROG_TYPE_RAW_TRACEPOINT

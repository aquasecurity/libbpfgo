//+build ignore
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1<<24);
} tester SEC(".maps");

SEC("tp/syscalls/sys_enter_dup")
int tracepoint__sys_enter_dup(struct trace_event_raw_sys_enter *args) {
	return 0;
}

SEC("raw_tp/sched_switch")
int raw_tracepoint__sched_switch(struct bpf_raw_tracepoint_args *args) {
	return 0;
}

SEC("kprobe/get_task_pid")
int kprobe__get_task_pid(struct pt_regs *ctx) {
	return 0;
}

SEC("kretprobe/get_task_pid")
int kretprobe__get_task_pid(struct pt_regs *ctx) {
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
	return 0;
}

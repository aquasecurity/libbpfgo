#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct bpf_iter_meta {
    struct seq_file *seq;
    __u64 session_id;
    __u64 seq_num;
} __attribute__((preserve_access_index));

struct bpf_iter__task {
    struct bpf_iter_meta *meta;
    struct task_struct *task;
} __attribute__((preserve_access_index));

struct seq_file;

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *parent;
    char comm[16];
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */

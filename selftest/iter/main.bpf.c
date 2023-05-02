//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

SEC("iter/task")
int iter__task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL)
        return 0;

    BPF_SEQ_PRINTF(seq, "%d\t%d\t%s\n", task->parent->pid, task->pid, task->comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

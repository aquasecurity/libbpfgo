//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

const char sleep_comm[] = "sleep";

SEC("iter/task")
int iter__task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL)
        return 0;

    // disregard all but "sleep"
    const int sleep_comm_size = sizeof(sleep_comm);
    for (int i = 0; i < sleep_comm_size; i++) {
        if (task->comm[i] != sleep_comm[i])
            return 0;
    }

    BPF_SEQ_PRINTF(seq, "%d\t%d\t%s\n", task->parent->pid, task->pid, task->comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

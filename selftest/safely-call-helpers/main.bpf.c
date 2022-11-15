//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


/*
Need:
- Big instr count (BPF_MAXINSNS defined in include/uapi/linux/bpf_common.h)
- bounded loops
- bpf cookie
- tracing prog
- lsm bpf progs
- inode/task/socket storage
- cgroup networking
*/

// Safely call helpers
SEC("fentry/__x64_sys_mmap")
int mmap_fentry(struct pt_regs *ctx)
{
    // 5.15+
    struct task_struct *current;
	struct pt_regs *regs;
    char *name;

    if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_kallsyms_lookup_name)
        && (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_kallsyms_lookup_name) == BPF_FUNC_kallsyms_lookup_name))
            {
                bpf_kallsyms_lookup_name(name, 5, 0, NULL);    
            }


	current = bpf_get_current_task_btf();
	regs = (struct pt_regs *) bpf_task_pt_regs(current);


    // 5.16+
    if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_kallsyms_lookup_name)
        && (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_kallsyms_lookup_name) == BPF_FUNC_kallsyms_lookup_name))
            {
                bpf_kallsyms_lookup_name(name, 5, 0, NULL);    
            }
            
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

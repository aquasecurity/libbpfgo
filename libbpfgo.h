#ifndef __LIBBPF_GO_H__
#define __LIBBPF_GO_H__

#ifdef __powerpc64__
    #define __SANE_USERSPACE_TYPES__ 1
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi

void set_print_fn();

struct ring_buffer *init_ring_buf(int map_fd, uintptr_t ctx);
struct perf_buffer *init_perf_buf(int map_fd, int page_cnt, uintptr_t ctx);

void get_internal_map_init_value(struct bpf_map *map, void *value);

int bpf_prog_attach_cgroup_legacy(int prog_fd, int target_fd, int type);
int bpf_prog_detach_cgroup_legacy(int prog_fd, int target_fd, int type);

//
// struct handlers
//

struct bpf_iter_attach_opts *bpf_iter_attach_opts_new(__u32 map_fd,
                                                      enum bpf_cgroup_iter_order order,
                                                      __u32 cgroup_fd,
                                                      __u64 cgroup_id,
                                                      __u32 tid,
                                                      __u32 pid,
                                                      __u32 pid_fd);
void bpf_iter_attach_opts_free(struct bpf_iter_attach_opts *opts);

struct bpf_object_open_opts *bpf_object_open_opts_new(const char *btf_file_path,
                                                      const char *kconfig_path,
                                                      const char *bpf_obj_name);
void bpf_object_open_opts_free(struct bpf_object_open_opts *opts);

#endif

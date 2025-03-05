#ifndef __VMLINUX_H__
#define __VMLINUX_H__
;
; // don't remove: clangd parsing bug https://github.com/clangd/clangd/issues/1167
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

enum {
    false = 0,
    true = 1,
};

typedef signed char __s8;
typedef __s8 s8;
typedef s8 int8_t;

typedef short int __s16;
typedef __s16 s16;
typedef s16 int16_t;

typedef int __s32;
typedef __s32 s32;
typedef s32 int32_t;

typedef long long int __s64;
typedef __s64 s64;
typedef s64 int64_t;

typedef unsigned char __u8;
typedef __u8 u8;
typedef u8 uint8_t;
typedef u8 u_int8_t;

typedef short unsigned int __u16;
typedef __u16 u16;
typedef __u16 __le16;
typedef __u16 __be16;
typedef u16 uint16_t;
typedef u16 u_int16_t;

typedef unsigned int __u32;
typedef unsigned int uint;
typedef __u32 u32;
typedef __u32 int32;
typedef __u32 __be32;
typedef u32 uint32_t;
typedef u32 u_int32_t;

typedef long long unsigned int __u64;
typedef __u64 u64;
typedef __u64 __le64;
typedef __u64 __be64;
typedef u64 uint64_t;
typedef u64 u_int64_t;

typedef long int __kernel_long_t;
typedef unsigned int __kernel_mode_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_long_t __kernel_off_t;
typedef __kernel_off_t off_t;

typedef long unsigned int __kernel_ulong_t;

typedef _Bool bool;

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

typedef __u16 __sum16;

typedef __u32 __wsum;

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

struct bpf_spin_lock {
    __u32 val;
};

struct bpf_raw_tracepoint_args {
    __u64 args[0];
};

enum {
    BPF_F_CURRENT_CPU = 4294967295,
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
    BPF_MAP_TYPE_USER_RINGBUF = 31,
    BPF_MAP_TYPE_CGRP_STORAGE = 32,
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

struct rb_node {
    long unsigned int __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};

struct bpf_iter_scx_dsq {
    u64 __opaque[6];
};

struct bpf_rb_root {
    __u64 __opaque[2];
};

struct bpf_list_head {
    __u64 __opaque[2];
};

struct bpf_list_node {
    __u64 __opaque[3];
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct scx_dsq_list_node {
    struct list_head node;
    u32 flags;
    u32 priv;
};

struct scx_dispatch_q;

struct bpf_iter_scx_dsq_kern {
    struct scx_dsq_list_node cursor;
    struct scx_dispatch_q *dsq;
    u64 slice;
    u64 vtime;
};

typedef struct {
    s64 counter;
} atomic64_t;

typedef atomic64_t atomic_long_t;

typedef struct {
    int counter;
} atomic_t;

enum scx_consts {
    SCX_DSP_DFL_MAX_BATCH = 32,
    SCX_DSP_MAX_LOOPS = 32,
    SCX_WATCHDOG_MAX_TIMEOUT = 7500,
    SCX_EXIT_BT_LEN = 64,
    SCX_EXIT_MSG_LEN = 1024,
    SCX_EXIT_DUMP_DFL_LEN = 32768,
    SCX_CPUPERF_ONE = 1024,
    SCX_OPS_TASK_ITER_BATCH = 32,
};

enum scx_cpu_preempt_reason {
    SCX_CPU_PREEMPT_RT = 0,
    SCX_CPU_PREEMPT_DL = 1,
    SCX_CPU_PREEMPT_STOP = 2,
    SCX_CPU_PREEMPT_UNKNOWN = 3,
};

enum scx_deq_flags {
    SCX_DEQ_SLEEP = 1ULL,
    SCX_DEQ_CORE_SCHED_EXEC = 4294967296ULL,
};

enum scx_dsq_id_flags {
    SCX_DSQ_FLAG_BUILTIN = 9223372036854775808ULL,
    SCX_DSQ_FLAG_LOCAL_ON = 4611686018427387904ULL,
    SCX_DSQ_INVALID = 9223372036854775808ULL,
    SCX_DSQ_GLOBAL = 9223372036854775809ULL,
    SCX_DSQ_LOCAL = 9223372036854775810ULL,
    SCX_DSQ_LOCAL_ON = 13835058055282163712ULL,
    SCX_DSQ_LOCAL_CPU_MASK = 4294967295ULL,
};

enum scx_dsq_iter_flags {
    SCX_DSQ_ITER_REV = 65536,
    __SCX_DSQ_ITER_HAS_SLICE = 1073741824,
    __SCX_DSQ_ITER_HAS_VTIME = 2147483648,
    __SCX_DSQ_ITER_USER_FLAGS = 65536,
    __SCX_DSQ_ITER_ALL_FLAGS = 3221291008,
};

enum scx_dsq_lnode_flags {
    SCX_DSQ_LNODE_ITER_CURSOR = 1,
    __SCX_DSQ_LNODE_PRIV_SHIFT = 16,
};

enum scx_enq_flags {
    SCX_ENQ_WAKEUP = 1ULL,
    SCX_ENQ_HEAD = 16ULL,
    SCX_ENQ_CPU_SELECTED = 1024ULL,
    SCX_ENQ_PREEMPT = 4294967296ULL,
    SCX_ENQ_REENQ = 1099511627776ULL,
    SCX_ENQ_LAST = 2199023255552ULL,
    __SCX_ENQ_INTERNAL_MASK = 18374686479671623680ULL,
    SCX_ENQ_CLEAR_OPSS = 72057594037927936ULL,
    SCX_ENQ_DSQ_PRIQ = 144115188075855872ULL,
};

enum scx_ent_dsq_flags {
    SCX_TASK_DSQ_ON_PRIQ = 1,
};

enum scx_ent_flags {
    SCX_TASK_QUEUED = 1,
    SCX_TASK_RESET_RUNNABLE_AT = 4,
    SCX_TASK_DEQD_FOR_SLEEP = 8,
    SCX_TASK_STATE_SHIFT = 8,
    SCX_TASK_STATE_BITS = 2,
    SCX_TASK_STATE_MASK = 768,
    SCX_TASK_CURSOR = -2147483648,
};

enum scx_exit_code {
    SCX_ECODE_RSN_HOTPLUG = 4294967296ULL,
    SCX_ECODE_ACT_RESTART = 281474976710656ULL,
};

enum scx_exit_kind {
    SCX_EXIT_NONE = 0,
    SCX_EXIT_DONE = 1,
    SCX_EXIT_UNREG = 64,
    SCX_EXIT_UNREG_BPF = 65,
    SCX_EXIT_UNREG_KERN = 66,
    SCX_EXIT_SYSRQ = 67,
    SCX_EXIT_ERROR = 1024,
    SCX_EXIT_ERROR_BPF = 1025,
    SCX_EXIT_ERROR_STALL = 1026,
};

enum scx_kf_mask {
    SCX_KF_UNLOCKED = 0,
    SCX_KF_CPU_RELEASE = 1,
    SCX_KF_DISPATCH = 2,
    SCX_KF_ENQUEUE = 4,
    SCX_KF_SELECT_CPU = 8,
    SCX_KF_REST = 16,
    __SCX_KF_RQ_LOCKED = 31,
    __SCX_KF_TERMINAL = 28,
};

enum scx_kick_flags {
    SCX_KICK_IDLE = 1,
    SCX_KICK_PREEMPT = 2,
    SCX_KICK_WAIT = 4,
};

enum scx_opi {
    SCX_OPI_BEGIN = 0,
    SCX_OPI_NORMAL_BEGIN = 0,
    SCX_OPI_NORMAL_END = 29,
    SCX_OPI_CPU_HOTPLUG_BEGIN = 29,
    SCX_OPI_CPU_HOTPLUG_END = 31,
    SCX_OPI_END = 31,
};

enum scx_ops_enable_state {
    SCX_OPS_ENABLING = 0,
    SCX_OPS_ENABLED = 1,
    SCX_OPS_DISABLING = 2,
    SCX_OPS_DISABLED = 3,
};

enum scx_ops_flags {
    SCX_OPS_KEEP_BUILTIN_IDLE = 1,
    SCX_OPS_ENQ_LAST = 2,
    SCX_OPS_ENQ_EXITING = 4,
    SCX_OPS_SWITCH_PARTIAL = 8,
    SCX_OPS_HAS_CGROUP_WEIGHT = 65536,
    SCX_OPS_ALL_FLAGS = 65551,
};

enum scx_ops_state {
    SCX_OPSS_NONE = 0,
    SCX_OPSS_QUEUEING = 1,
    SCX_OPSS_QUEUED = 2,
    SCX_OPSS_DISPATCHING = 3,
    SCX_OPSS_QSEQ_SHIFT = 2,
};

enum scx_pick_idle_cpu_flags {
    SCX_PICK_IDLE_CORE = 1,
};

enum scx_public_consts {
    SCX_OPS_NAME_LEN = 128ULL,
    SCX_SLICE_DFL = 20000000ULL,
    SCX_SLICE_INF = 18446744073709551615ULL,
};

enum scx_rq_flags {
    SCX_RQ_ONLINE = 1,
    SCX_RQ_CAN_STOP_TICK = 2,
    SCX_RQ_BAL_PENDING = 4,
    SCX_RQ_BAL_KEEP = 8,
    SCX_RQ_BYPASSING = 16,
    SCX_RQ_IN_WAKEUP = 65536,
    SCX_RQ_IN_BALANCE = 131072,
};

enum scx_task_state {
    SCX_TASK_NONE = 0,
    SCX_TASK_INIT = 1,
    SCX_TASK_READY = 2,
    SCX_TASK_ENABLED = 3,
    SCX_TASK_NR_STATES = 4,
};

enum scx_tg_flags {
    SCX_TG_ONLINE = 1,
    SCX_TG_INITED = 2,
};

enum scx_wake_flags {
    SCX_WAKE_FORK = 4,
    SCX_WAKE_TTWU = 8,
    SCX_WAKE_SYNC = 16,
};

struct sched_ext_entity {
    struct scx_dispatch_q *dsq;
    struct scx_dsq_list_node dsq_list;
    struct rb_node dsq_priq;
    u32 dsq_seq;
    u32 dsq_flags;
    u32 flags;
    u32 weight;
    s32 sticky_cpu;
    s32 holding_cpu;
    u32 kf_mask;
    struct task_struct *kf_tasks[2];
    atomic_long_t ops_state;
    struct list_head runnable_node;
    long unsigned int runnable_at;
    u64 core_sched_at;
    u64 ddsp_dsq_id;
    u64 ddsp_enq_flags;
    u64 slice;
    u64 dsq_vtime;
    bool disallow;
    struct cgroup *cgrp_moving_from;
    struct list_head tasks_node;
};

struct scx_cpu_acquire_args;

struct scx_cpu_release_args;

struct scx_init_task_args;

struct scx_exit_task_args;

struct scx_dump_ctx;

struct scx_cgroup_init_args;

struct scx_exit_info;

struct scx_bstr_buf {
    u64 data[12];
    char line[1024];
};

struct scx_cgroup_init_args {
    u32 weight;
};

struct scx_cpu_acquire_args {
};

struct scx_cpu_release_args {
    enum scx_cpu_preempt_reason reason;
    struct task_struct *task;
};

struct scx_dsp_buf_ent {
    struct task_struct *task;
    long unsigned int qseq;
    u64 dsq_id;
    u64 enq_flags;
};

struct scx_dsp_ctx {
    struct rq *rq;
    u32 cursor;
    u32 nr_tasks;
    struct scx_dsp_buf_ent buf[0];
};

struct scx_dump_ctx {
    enum scx_exit_kind kind;
    s64 exit_code;
    const char *reason;
    u64 at_ns;
    u64 at_jiffies;
};

struct scx_dump_data {
    s32 cpu;
    bool first;
    s32 cursor;
    struct seq_buf *s;
    const char *prefix;
    struct scx_bstr_buf buf;
};

struct scx_exit_info {
    enum scx_exit_kind kind;
    s64 exit_code;
    const char *reason;
    long unsigned int *bt;
    u32 bt_len;
    char *msg;
    char *dump;
};

struct scx_exit_task_args {
    bool cancelled;
};

struct scx_init_task_args {
    bool fork;
    struct cgroup *cgroup;
};

struct pin_cookie {
};

struct rq_flags {
    long unsigned int flags;
    struct pin_cookie cookie;
    unsigned int clock_update_flags;
};

struct scx_task_iter {
    struct sched_ext_entity cursor;
    struct task_struct *locked;
    struct rq *rq;
    struct rq_flags rf;
    u32 cnt;
};

struct cpumask {
    long unsigned int bits[128];
};

typedef struct cpumask cpumask_t;

struct bpf_iter_bits {
    __u64 __opaque[2];
};

struct sched_ext_ops {
    s32 (*select_cpu)(struct task_struct *, s32, u64);
    void (*enqueue)(struct task_struct *, u64);
    void (*dequeue)(struct task_struct *, u64);
    void (*dispatch)(s32, struct task_struct *);
    void (*tick)(struct task_struct *);
    void (*runnable)(struct task_struct *, u64);
    void (*running)(struct task_struct *);
    void (*stopping)(struct task_struct *, bool);
    void (*quiescent)(struct task_struct *, u64);
    bool (*yield)(struct task_struct *, struct task_struct *);
    bool (*core_sched_before)(struct task_struct *, struct task_struct *);
    void (*set_weight)(struct task_struct *, u32);
    void (*set_cpumask)(struct task_struct *, const struct cpumask *);
    void (*update_idle)(s32, bool);
    void (*cpu_acquire)(s32, struct scx_cpu_acquire_args *);
    void (*cpu_release)(s32, struct scx_cpu_release_args *);
    s32 (*init_task)(struct task_struct *, struct scx_init_task_args *);
    void (*exit_task)(struct task_struct *, struct scx_exit_task_args *);
    void (*enable)(struct task_struct *);
    void (*disable)(struct task_struct *);
    void (*dump)(struct scx_dump_ctx *);
    void (*dump_cpu)(struct scx_dump_ctx *, s32, bool);
    void (*dump_task)(struct scx_dump_ctx *, struct task_struct *);
    s32 (*cgroup_init)(struct cgroup *, struct scx_cgroup_init_args *);
    void (*cgroup_exit)(struct cgroup *);
    s32 (*cgroup_prep_move)(struct task_struct *, struct cgroup *, struct cgroup *);
    void (*cgroup_move)(struct task_struct *, struct cgroup *, struct cgroup *);
    void (*cgroup_cancel_move)(struct task_struct *, struct cgroup *, struct cgroup *);
    void (*cgroup_set_weight)(struct cgroup *, u32);
    void (*cpu_online)(s32);
    void (*cpu_offline)(s32);
    s32 (*init)(void);
    void (*exit)(struct scx_exit_info *);
    u32 dispatch_max_batch;
    u64 flags;
    u32 timeout_ms;
    u32 exit_dump_len;
    u64 hotplug_seq;
    char name[128];
};

enum bpf_struct_ops_state {
    BPF_STRUCT_OPS_STATE_INIT = 0,
    BPF_STRUCT_OPS_STATE_INUSE = 1,
    BPF_STRUCT_OPS_STATE_TOBEFREE = 2,
    BPF_STRUCT_OPS_STATE_READY = 3,
};

struct refcount_struct {
    atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct bpf_struct_ops_common_value {
    refcount_t refcnt;
    enum bpf_struct_ops_state state;
};

struct bpf_struct_ops_sched_ext_ops {
    struct bpf_struct_ops_common_value common;
    long : 64;
    long : 64;
    long : 64;
    long : 64;
    long : 64;
    long : 64;
    long : 64;
    struct sched_ext_ops data;
    long : 64;
    long : 64;
    long : 64;
};

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *parent;
    struct sched_ext_entity scx;
    short unsigned int migration_disabled;
    char comm[16];
};

// NETWORK

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
    volatile unsigned char skc_state;
    int skc_bound_dev_if;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

#define ETH_P_IP 0x0800

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
};

//
// COMPLETE NETWORK TYPES
//
// NOTE: It is not required that types are complete in this file, as tracee uses
//       CO-RE for calculating struct field offsets. The thing is: for protocol
//       headers, sometimes, the type is an exact copy of the header that will
//       receive a payload copy. This makes it impossible not to have the full
//       types declared. Also, something else to note: protocol header types are
//       or, at least, should be, immutable among different kernel versions.
//

enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
    TCP_NEW_SYN_RECV = 12,
    TCP_MAX_STATES = 13,
};

enum sock_type {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
};

enum {
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_MPLS = 137,
    IPPROTO_ETHERNET = 143,
    IPPROTO_RAW = 255,
    IPPROTO_MPTCP = 262,
    IPPROTO_MAX = 263,
};

enum {
    TCPF_ESTABLISHED = 2,
    TCPF_SYN_SENT = 4,
    TCPF_FIN_WAIT1 = 16,
    TCPF_FIN_WAIT2 = 32,
    TCPF_TIME_WAIT = 64,
    TCPF_CLOSE = 128,
    TCPF_CLOSE_WAIT = 256,
    TCPF_LAST_ACK = 512,
    TCPF_LISTEN = 1024,
    TCPF_CLOSING = 2048,
    TCPF_NEW_SYN_RECV = 4096,
};

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    union {
        struct bpf_flow_keys *flow_keys;
    };
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
    union {
        struct bpf_sock *sk;
    };
    __u32 gso_size;
};

enum bpf_hdr_start_off {
    BPF_HDR_START_MAC = 0,
    BPF_HDR_START_NET = 1,
};

struct iphdr {
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

struct ipv6hdr {
    __u8 priority : 4;
    __u8 version : 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4;
    __u16 doff : 4;
    __u16 fin : 1;
    __u16 syn : 1;
    __u16 rst : 1;
    __u16 psh : 1;
    __u16 ack : 1;
    __u16 urg : 1;
    __u16 ece : 1;
    __u16 cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
};

struct icmpv6_echo {
    __be16 identifier;
    __be16 sequence;
};

struct icmpv6_nd_advt {
    __u32 reserved : 5;
    __u32 override : 1;
    __u32 solicited : 1;
    __u32 router : 1;
    __u32 reserved2 : 24;
};

struct icmpv6_nd_ra {
    __u8 hop_limit;
    __u8 reserved : 3;
    __u8 router_pref : 2;
    __u8 home_agent : 1;
    __u8 other : 1;
    __u8 managed : 1;
    __be16 rt_lifetime;
};

struct icmp6hdr {
    __u8 icmp6_type;
    __u8 icmp6_code;
    __sum16 icmp6_cksum;
    union {
        __be32 un_data32[1];
        __be16 un_data16[2];
        __u8 un_data8[4];
        struct icmpv6_echo u_echo;
        struct icmpv6_nd_advt u_nd_advt;
        struct icmpv6_nd_ra u_nd_ra;
    } icmp6_dataun;
};

#if defined(__TARGET_ARCH_x86)

struct pt_regs {
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int orig_ax;
    long unsigned int ip;
    long unsigned int cs;
    long unsigned int flags;
    long unsigned int sp;
    long unsigned int ss;
};

#elif defined(__TARGET_ARCH_arm64)

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            u64 regs[31];
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
    u64 orig_x0;
    s32 syscallno;
    u32 unused2;
    u64 orig_addr_limit;
    u64 pmr_save;
    u64 stackframe[2];
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

#endif

#pragma clang attribute pop

#endif

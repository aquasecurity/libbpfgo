#ifndef __VMLINUX_H__
#define __VMLINUX_H__
;
; // don't remove: clangd parsing bug https://github.com/clangd/clangd/issues/1167
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

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

enum
{
    BPF_F_CURRENT_CPU = 4294967295,
};

enum bpf_map_type
{
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

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *parent;
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

enum xdp_action
{
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

enum
{
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

enum sock_type
{
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
    SOCK_RDM = 4,
    SOCK_SEQPACKET = 5,
    SOCK_DCCP = 6,
    SOCK_PACKET = 10,
};

enum
{
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

enum
{
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

enum bpf_hdr_start_off
{
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

#pragma clang attribute pop

#endif

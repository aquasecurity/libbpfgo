//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} perfbuffer SEC(".maps");

SEC("cgroup_skb/ingress")
int cgroup__skb_ingress(struct __sk_buff *ctx)
{
    if (ctx->protocol != bpf_htons(ETH_P_IP)) // ethernet (IP) only
        return 1;

    struct bpf_sock *sk = ctx->sk;
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/ingress: could not get bpf_sock");
        return 1;
    }

    sk = bpf_sk_fullsock(sk);
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/ingress: could not get full bpf_sock");
        return 1;
    }

    struct iphdr ip = {0};
    struct icmphdr icmp = {0};

    u32 s_iphdr = bpf_core_type_size(struct iphdr);
    u32 s_icmphdr = bpf_core_type_size(struct icmphdr);

    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, s_iphdr, BPF_HDR_START_NET))
        return 1;

    // clang-format off

    switch (ip.protocol) {
        case IPPROTO_ICMP:
            if (bpf_skb_load_bytes_relative(ctx,
                                            s_iphdr,
                                            &icmp,
                                            s_icmphdr,
                                            BPF_HDR_START_NET))
                return 1;

            u32 bleh = 20220823;
            bpf_perf_event_output(ctx,
                                  &perfbuffer,
                                  BPF_F_CURRENT_CPU,
                                  &bleh,
                                  sizeof(bleh));
            break;
    }

    // clang-format on

    return 1;
}

char LICENSE[] SEC("license") = "GPL";

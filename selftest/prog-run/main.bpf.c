//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tc")
int test_tc(struct __sk_buff *skb)
{
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    if (data + 4 > data_end) {
        return -1;
    }
    if (*(__u32 *) data == 0xdeadbeef) {
        char new_data[] = {0x01, 0x02, 0x03, 0x04};
        bpf_skb_store_bytes(skb, 0, new_data, 4, 0);
        bpf_skb_change_tail(skb, 14, 0);
        return 1;
    }
    return 2;
}

char LICENSE[] SEC("license") = "GPL";

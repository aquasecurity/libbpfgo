#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//#include <arpa/inet.h>
//#include <netinet/in.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct data_t {
        char comm[16];          // command (task_comm_len)
        u32  pid;               // proccess id
        u32  uid;               // user id
        u32  gid;               // group id
        u32  loginuid;          // real user (login/terminal)
        u8   family;            // network family
        u8   proto;             // protocol (sock.h: u8 older, u16 newer)
        u16  sport;             // source port
        u16  dport;             // destination port
        u32  saddr;             // source address
        struct in6_addr saddr6; // source address (IPv6)
        u32  daddr;             // destination address
        struct in6_addr daddr6; // destination address (IPv6)
        u8   thesource;         // I am the one originating packet
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * NOTE: keeping this, for now, compatible to v4.15 kernels, that is why it
 * does not have all ebpf latest features
 */

#define BASE \
	struct data_t data = {};					\
	struct task_struct *task = (void *) bpf_get_current_task();	\
	u64 id1 = bpf_get_current_pid_tgid(); 				\
	u64 id2 = bpf_get_current_uid_gid(); 				\
	u32 tgid = id1 >> 32, pid = id1; 				\
	u32 gid = id2 >> 32, uid = id2; 				\
	data.pid = tgid;						\
	data.uid = uid;							\
	data.uid = gid;							\
	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val); \
	bpf_probe_read_kernel_str(&data.comm, 16, task->comm);

#define COMMON \
	BASE								\
	struct inet_sock *inet = inet_sk(sk);				\
	struct tcp_sock *tp = tcp_sk(sk);				\
	struct flowi4 *fl4= &inet->cork.fl.u.ip4;			\
	struct flowi6 *fl6= &inet->cork.fl.u.ip6;			\
	struct ipv6_pinfo *np = inet6_sk(sk);				\

#undef htons
#define htons(x) ((__be16)(__u16)(x))

static __always_inline bool
check_for_zeros_v4(struct data_t *gdata)
{
	if (gdata->sport == 0 || gdata->dport == 0)
		return 1;
	if (gdata->saddr == 0 || gdata->daddr == 0)
		return 1;

	return 0;
}

static __always_inline bool
check_for_zeros_v6(struct data_t *gdata)
{
	if (gdata->sport == 0 || gdata->dport == 0)
		return 1;

	if (gdata->saddr6.in6_u.u6_addr32[0] == 0xFFFF || gdata->daddr6.in6_u.u6_addr32[0] == 0xFFFF)
		return 1;

	return 0;
}

static __always_inline struct inet_sock *
inet_sk(const struct sock *sk)
{
	struct inet_sock *ptr;

	bpf_probe_read_kernel(&ptr, sizeof (void *), &sk);

	return ptr;
}

static __always_inline struct tcp_sock *
tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static __always_inline struct ipv6_pinfo *
inet6_sk(const struct sock *__sk)
{
	struct inet_sock *inet = inet_sk(__sk);
	struct ipv6_pinfo *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(void *), &inet->pinet6);

	return ptr;
}

static inline unsigned char *
skb_transport_header(const struct sk_buff *skb)
{
	u16 transp_header;
	unsigned char *head;

	bpf_probe_read_kernel(&head, sizeof(void *), &skb->head);
	bpf_probe_read_kernel(&transp_header, sizeof(u16), &skb->transport_header);

	return head + transp_header;
}

static inline unsigned char *
skb_network_header(const struct sk_buff *skb)
{
	u16 net_header;
	unsigned char *head;

	bpf_probe_read_kernel(&head, sizeof(void *), &skb->head);
	bpf_probe_read_kernel(&net_header, sizeof(u16), &skb->network_header);

	return head + net_header;
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}

// TCPv4/TCPv6 outbound: probe compatible to v4.15 and v5.8

static __always_inline int
tcp_connect_enter(struct pt_regs *ctx, struct sock *sk)
{
	COMMON;

	volatile u8 skc_state;	// sk_type is bitfield, guess if this is UDP or TCP

	bpf_probe_read_kernel((u8 *) &skc_state, sizeof(u8), (u8 *) &sk->__sk_common.skc_state);
	if (skc_state != 2)	// TCP_SYN_SENT
		return 0;

	data.thesource = 1;	// OUTBOUND
	data.proto = 6;		// IPPROTO_TCP

	bpf_probe_read_kernel(&data.family, sizeof(u8), &sk->__sk_common.skc_family);

	switch (data.family) {
	case 2: // AF_INET
		bpf_probe_read_kernel(&data.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&data.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &sk->__sk_common.skc_dport);
		if (check_for_zeros_v4(&data))
			return 0;
		break;
	case 10: // AF_INET6
		bpf_probe_read_kernel(&data.saddr6, sizeof(data.saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_probe_read_kernel(&data.daddr6, sizeof(data.daddr6), &sk->__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &sk->__sk_common.skc_dport);
		if (check_for_zeros_v6(&data))
			return 0;
		break;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	return tcp_connect_enter(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";

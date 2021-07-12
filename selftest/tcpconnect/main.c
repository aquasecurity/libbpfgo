#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "main.skel.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define _wrapout(nl, ...)               \
{                                       \
        fprintf(stdout, __VA_ARGS__);   \
        if (nl)                         \
        fprintf(stdout, "\n");          \
}

#define _wrapout0(...) _wrapout(0, __VA_ARGS__)
#define _wrapout1(...) _wrapout(1, __VA_ARGS__)

#define wrapout  _wrapout1
#define here     _wrapout1("line %d, file %s, function %s", __LINE__, __FILE__, __func__)
#define debug(a) _wrapout1("%s (line %d, file %s, function %s)", a, __LINE__, __FILE__, __func__)

#define exiterr(...)            \
{                               \
        here;                   \
        exit(1);                \
}

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

static int bpfverbose = 0;
static volatile bool exiting;
static volatile bool found;

static int get_pid_max(void)
{
	FILE *f;
	int pid_max = 0;

	if ((f = fopen("/proc/sys/kernel/pid_max", "r")) == NULL)
		exiterr("failed to open proc_sys pid_max");

	if (fscanf(f, "%d\n", &pid_max) != 1)
		exiterr("failed to read proc_sys pid_max");

	fclose(f);

	return pid_max;
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

char *ipv4_str(struct in_addr *addr)
{
	char temp[INET_ADDRSTRLEN];

	memset(temp, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, addr, temp, INET_ADDRSTRLEN);

	return (char *) strdup(temp);
}

char *ipv6_str(struct in6_addr *addr)
{
	char temp[INET6_ADDRSTRLEN];

	memset(temp, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, addr, temp, INET6_ADDRSTRLEN);

	return (char *) strdup(temp);
}

static int output(struct data_t *e)
{
	struct in_addr src, dst;
	u16 sport = htons(e->sport);
	u16 dport = htons(e->dport);
	char *src_str = NULL, *dst_str = NULL;

	src.s_addr = e->saddr;
	dst.s_addr = e->daddr;

	switch (e->family) {
		case AF_INET:
			src_str = ipv4_str(&src);
			dst_str = ipv4_str(&dst);
			break;
		default:
			return 0;
	}

	wrapout("%s (pid: %u) (loginuid: %u) | (%u) %s (%u) => %s (%u)",
			e->comm, e->pid, e->loginuid, (u8) e->proto,
			src_str, sport, dst_str, dport);

	if (strstr(dst_str, "127.0.0.1")) {
		if (dport == 12345) {
			found = 1; // found the magic connection
		}
	}

	free(src_str);
	free(dst_str);

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}

int usage(int argc, char **argv)
{
	fprintf(stdout,
		"\n"
		"Syntax: %s [options]\n"
		"\n"
		"\t[options]:\n"
		"\n"
		"\t-v: bpf verbose mode\n"
		"\n",
		argv[0]);

	exit(0);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct data_t *e = data;

	output(e);

	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void trap(int what)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	int opt, err = 0, pid_max;
	struct main_bpf *main;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;

	while ((opt = getopt(argc, argv, "hvd")) != -1) {
		switch(opt) {
			case 'v':
				bpfverbose = 1;
				break;
			case 'h':
			default:
				usage(argc, argv);
		}
	}

	signal(SIGINT, trap);
	signal(SIGTERM, trap);

	fprintf(stdout, "Listening for tcp_connect(), <Ctrl-C> or or SIG_TERM to end it.\n");

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		exiterr("failed to increase rlimit: %d", err);

	if ((pid_max = get_pid_max()) < 0)
		exiterr("failed to get pid_max");

	// create BPF module using BPF object file
	if (!(main = main_bpf__open()))
		exiterr("failed to open BPF object");

	// load BPF object from BPF module
	if ((err = main_bpf__load(main)))
		exiterr("failed to load BPF object: %d\n", err);

	// attach to BPF program to kprobe
	if ((err = main_bpf__attach(main)))
		exiterr("failed to attach\n");

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;

	// start perf event polling (call handle_event & handle_lost_events on fd activity)
	pb = perf_buffer__new(bpf_map__fd(main->maps.events), 16 /* BUFFER PAGES */, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while (1) {
		if ((err = perf_buffer__poll(pb, 100)) < 0) {
			err = 1; // real error
			goto cleanup;
		}

		if (exiting) {
			err = 1; // not supposed to exit until magic connection
			goto cleanup;
		}

		if (found) {
			err = 0; // test succeeded
			goto cleanup;
		}
	}

cleanup:
	perf_buffer__free(pb);
	main_bpf__destroy(main);
	exit(err);
}

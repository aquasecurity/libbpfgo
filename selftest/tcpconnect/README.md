## libbpfgo: tcpconnect example

### Introduction

The idea behind this test directory is to document how you can migrate from a C eBPF based code, using [libbpf](https://github.com/libbpf/libbpf), to a pure golang eBPF code, using [libbpfgo](https://github.com/aquasecurity/libbpfgo). You may also read the Makefile to better understand how to build static and dynamic Go binaries with [libbpfgo](https://github.com/aquasecurity/libbpfgo).

The directory structure is this:

* main.bpf.o: the eBPF program loaded to the kernel
* main.go: the Go version of the userland program
* main.c: the C version of the userland progam

Both main.go and main.c programs should behave similarly, if not identically.

There are better places to learn eBPF, like:

1. https://ebpf.io/what-is-ebpf
1. https://ebpf.io/what-is-ebpf#introduction-to-ebpf
1. https://ebpf.io/what-is-ebpf#maps
1. https://ebpf.io/what-is-ebpf#why-ebpf
1. https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
1. https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html

This Readme file will quickly explain how this test works, so it can serve you as a reference for building a new test, or a new [libbpfgo](https://github.com/aquasecurity/libbpfgo) application.

The main eBPF structures to have in mind are:

* `bpf object` will contain bpf_programs and bpf_maps and more.
* `bpf program` is one non inline function from `main.bpf.c`.
* `bpf map` is a data structure shared between eBPF programs and userland.

### main.bpf.c

This is the file that will be compiled into eBPF binary object and loaded into the kernel for its eBPF JIT compiler to transform it to the current running architecture. The eBPF byte code contains different "programs", one per non-inline function, and each will run triggered by different events within the kernel.

The eBPF programs running inside the kernel may extract information - or, sometimes, take actions - and submit to userland through the use shared structures called [eBPF MAPS](https://ebpf.io/what-is-ebpf#map).

In this test example, the structure used for this communication to happen is the one below.

```C
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
```

This means that both, the eBPF program, and the userland code, need to know about this structure, so they can communicate.

> Note: there are different types of events which an eBPF program can be attached to (links) and different types of maps that can be used to exchange data. I'm not entering that topic here and this example uses simple ones.

From the snippet below:

```C
SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	return tcp_connect_enter(ctx, sk);
}
```

We are creating an eBPF program of name **tcp_connect**, it will be of type **kprobe** and will be linked to the kernel function **tcp_connect** (its event). Each time the probe is triggered, it calls an inline function passing the function arguments.

In the inline function:

```C
static __always_inline int
tcp_connect_enter(struct pt_regs *ctx, struct sock *sk)
{
    ...
	bpf_probe_read_kernel(&data.family, sizeof(u8), &sk->__sk_common.skc_family);
	...

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}
```

We read things from the kernel and share with userland through a simple eBPF array map called 'perf event array':

> Note: Like said previously, eBPF maps are data structures, of different kind/type, existing in kernel and accessible from eBPF programs and userland.

```C
`struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps")
```

Now, to the userland code...

## main.c

Through the direct usage of [libbpf](https://github.com/libbpf/libbpf), the main.c code will consume the perf events described in previous session. 

Initially [libbpf](https://github.com/libbpf/libbpf) library has to:

1. deal with embedded bytecode of eBPF programs (if using skeleton)
1. load eBPF object into the kernel (containing 1 or more programs)
1. create 1 link per existing eBPF program (program <-> kernel event)
1. create in-kernel eBPF maps based in the eBPF object 
1. run the userland portion of your program

This is done by the following calls:

```C
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
```

> **Note**: This example has only 1 eBPF program called `tcp_connect`, linked to a `kprobe` event attached to the kernel function `tcp_connect`.
 
The [libbpf](https://github.com/libbpf/libbpf) library has the concept of [eBPF skeleton](https://lwn.net/Articles/806911/). It will load all your programs and create all your maps automatically with single calls to the library. If you prefer, you may also specificy the eBPF programs (from `main.bpf.c`) you would like to load and which maps to create, one by one.

After initialization, it is time to configure a perf event polling logic:

```C
pb_opts.sample_cb = handle_event;
pb_opts.lost_cb = handle_lost_events;

pb = perf_buffer__new(bpf_map__fd(main->maps.events), 16, &pb_opts);

while (1) {

    if ((err = perf_buffer__poll(pb, 100)) < 0) {
        err = 1; // real error
        goto cleanup;
    }
    ...
```

This is similar to any other select()/poll() logic. The poll waits for the eBPF map (**events**) event to happen through the map fd and calls the callback function.

Callback function deals with the data sent through eBPF map (**events**) in **data_t** format, showing information caught from the kernel.

So, for the **tcpconnect** example, every time `main.bpf.c` **tcp_connect_enter()** function submits a perf event, because the kprobe **tcp_connect** was triggered, the userland code receives the event data (struct data_t format) through shared perf event array eBPF map **events**.

The callback will then handle the received - from eBPF program - data:

```C
static int output(struct data_t *e)
{
	struct in_addr src, dst;
	u16 sport = htons(e->sport);
	u16 dport = htons(e->dport);
	char *src_str = NULL, *dst_str = NULL;

	src.s_addr = e->saddr; // e->saddr comes from eBPF
	dst.s_addr = e->daddr; // e->daddr comes from eBPF

	switch (e->family) {   // e->family comes from eBPF
		case AF_INET:
			src_str = ipv4_str(&src);
			dst_str = ipv4_str(&dst);
			break;
		default:
			return 0;
	}
	...
```

### main.go

Now that you know how an eBPF program works, and how the userland code made with [libbpf](https://github.com/libbpf/libbpf) works, it is time to show how to make the same program using [libbpfgo](https://github.com/aquasecurity/libbpfgo).

With [libbpfgo](https://github.com/aquasecurity/libbpfgo) we have 1 main object, the **BPF Module**, and other objects representing data structures from [libbpf](https://github.com/libbpf/libbpf), being the most important ones:

```go
    var bpfModule *bpf.Module       // wrapper for the bpf_object structure
    var bpfMapEvents *bpf.BPFMap    // wrapper for the bpf_maps structure
    var bpfProg *bpf.BPFProg        // wrapper for the bpf_program structure
```

Being a wrapper to [libbpf](https://github.com/libbpf/libbpf), it is expected [libbpfgo](https://github.com/aquasecurity/libbpfgo) initialization to be similar to the C code:

```go
	// create BPF module using BPF object file
	bpfModule, erro = bpf.NewModuleFromFile("main.bpf.o")
	
	defer bpfModule.Close()

	// BPF map "events": resize it before object is loaded
	bpfMapEvents, erro = bpfModule.GetMap("events")
	
	erro = bpfMapEvents.Resize(8192)

	// load BPF object from BPF module
	bpfModule.BPFLoadObject();

	// get BPF program from BPF object
	bpfProgTcpConnect, erro = bpfModule.GetProgram("tcp_connect")

	// attach to BPF program to kprobe
	_, erro = bpfProgTcpConnect.AttachKprobe("tcp_connect")
```

Like said earlier, by using [libbpf](https://github.com/libbpf/libbpf) you can either use skeleton OR provide each eBPF object, program and map to be created and loaded, like [libbpfgo](https://github.com/aquasecurity/libbpfgo) does.

This code snippet:

1. creates an eBPF module **bpfModule** and defers its closure
1. creates **bpfMapEvents** map object from the already created **events** map
1. loads **main.bpf.o** (eBPF compiled) object into kernel and all its programs
1. new **bpfProgramTcpConnect** is created from **tcp_connect** eBPF program
1. **bpfProgramTcpConnect** is attached to **tcp_connect** kprobe event 
1. attachment creates a BPFlink (not being used in this example).

After initialization, it is time to do what Go does best: event oriented work:

```Go
// channel for events (and lost events)
eventsChannel = make(chan []byte)
lostChannel = make(chan uint64)

perfBuffer, err = bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)

// start perf event polling (will receive events through eventChannel)
perfBuffer.Start()
```

Easier than the [libbpf](https://github.com/libbpf/libbpf) C version, with [libbpfgo](https://github.com/aquasecurity/libbpfgo) the polling logic is hidden. We simply create a **perfBuffer** object from **bpfModule**, for a specific map **events**, and specify which channels should be used for events or lost events:

```go

for dataRaw := range eventsChannel {
	var dt data
	var dataBuffer *bytes.Buffer

	dataBuffer = bytes.NewBuffer(dataRaw)

	err = binary.Read(dataBuffer, binary.LittleEndian, &dt)
	if err != nil {
		fmt.Println(err)
		continue
	}

	var bsport = make([]byte, 2)
	var bdport = make([]byte, 2)
	binary.BigEndian.PutUint16(bsport, dt.SPort)
	binary.BigEndian.PutUint16(bdport, dt.DPort)

	godata := gdata{
		Comm:     string(bytes.TrimRight(dt.Comm[:], "\x00")),
		Pid:      uint(dt.Pid),
		Uid:      uint(dt.Uid),
		Gid:      uint(dt.Gid),
		LoginUid: uint(dt.LoginUid),
		Family:   uint(dt.Family),
		Proto:    uint(dt.Proto),
		SPort:    uint(binary.LittleEndian.Uint16(bsport)),
		DPort:    uint(binary.LittleEndian.Uint16(bdport)),
	}
```

> **Note**: because [libbpfgo](https://github.com/aquasecurity/libbpfgo) uses #cgo, it is mandatory that you convert the "struct data_t", coming from the events channel, to a go struct (using go primitives)

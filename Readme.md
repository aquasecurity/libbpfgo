# libbpfgo

<img src="docs/images/aqua-tux.png" width="150" height="auto">

----

libbpfgo is a Go library for Linux's [eBPF](https://ebpf.io/) project. It was created for [Tracee](https://github.com/aquasecurity/tracee), our open source Runtime Security, and eBPF tracing tool, written in Go. If you are interested in eBPF and its applications, check out Tracee at Github: [https://github.com/aquasecurity/tracee](https://github.com/aquasecurity/tracee).

libbpfgo is built around [libbpf](https://github.com/libbpf/libbpf) - the standard library for interacting with eBPF programs from userspace - which is a C library maintained in Linux upstream. We have created libbpfgo as a thin Go wrapper around the libbpf project.

## Installing

libbpfgo uses CGO to interop with libbpf and will expect to be linked with libbpf at run or link time. Simply importing libbpfgo is not enough to get started, and you will need to fulfill the required dependency in one of the following ways:

1. Install libbpf as a shared object in the system. Libbpf may already be packaged for your distribution and, if not, you can build and install from source. More info [here](https://github.com/libbpf/libbpf).
1. Embed libbpf into your Go project as a vendored dependency. This means that the libbpf code is statically linked into the resulting binary, and there are no runtime dependencies.  [Tracee](https://github.com/aquasecurity/tracee) takes this approach.

## Concepts

libbpfgo tries to make it natural for Go developers to use, by abstracting away C technicalities. For example, it will translate low level return codes into Go `error`, it will organize functionality around Go `struct`, and it will use `channel` as to let you consume events.

In a high level, this is a typical workflow for working with the library:

1. Compile your bpf program into an object file.
1. Initialize a `Module` struct - that is a unit of BPF functionality around your compiled object file.
1. Load bpf programs from the object file using the `BPFProg` struct.
1. Attach `BPFProg` to system facilities, for example to "raw tracepoints" or "kprobes" using the `BPFProg`'s associated functions.
1. Instantiate and manipulate BPF Maps via the `BPFMap` struct and it's associated methods.
1. Instantiate and manipulate Perf Buffer for communicating events from your BPF program to the driving userspace program, using the `RingBuffer` struct and it's associated objects.

## Example

```go
// initializing
import bpf "github.com/aquasecurity/libbpfgo"
...
bpfModule := bpf.NewModuleFromFile(bpfObjectPath)
bpfModule.BPFLoadObject()

// maps
mymap, _ := bpfModule.GetMap("mymap")
mymap.Update(key, value)

// ring buffer
rb, _ := bpfModule.InitRingBuffer("events", eventsChannel, buffSize)
rb.Start()
e := <-eventsChannel
```

Please check our github milestones for an idea of the project roadmap. The general goal is to fully implement/expose libbpf's API in Go as seamlessly as possible.

## Learn more

- [How to Build eBPF Programs with libbpfgo](https://blog.aquasec.com/libbpf-ebpf-programs).
- [selftests](./selftest) are small program using libbpfgo and might be good usage examples.
- [tracee-ebpf](https://github.com/aquasecurity/tracee/tree/main/tracee-ebpf) is a robust consumer of this project.
- Feel free to ask questions by creating a new [Discussion](https://github.com/aquasecurity/libbpfgo/discussions), we'd love to help.

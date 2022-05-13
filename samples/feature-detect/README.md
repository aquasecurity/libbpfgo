# Feature Detection PoC

This is a proof of concept for an idea of how tracee can support using featuring detection to decide what BPF programs to load.

## Goal

To be able to take advantage of new BPF program types on kernels that support them, without sacraficing support for older kernels, and without having our BPF code be a total mess.

## Challenges

We cannot rely on macros to check kernel version to determine if a particular program type, map type, or other BPF feature is supported. 

We cannot break compatibility with older kernels (4.18+).

## Technical details of approach

The idea is to allow for multiple, seperate BPF programs which produce the same event. For example, two BPF programs that each produce an event representing a `mmap` call, one which uses the older 'kprobe' program type, and one which attaches using 'fentry' and the 'tracing' program type. These two programs would be written very in different ways as the latter allows for direct memory access, and the kprobe program does not.

In order to do so, we would use iteration within the BPF object, finding programs that correspond to particular events via the program name. The programs would be tested to see if the program type is supported and loaded based on which is the preferable type.

__For example__, the two programs that each produce a `mmap` event would be named `mmap_fentry` and `mmap_kprobe`. They would both be compiled and contained in the resulting BPF object. On tracee startup if the user specified that they want the `mmap` event, tracee would look for BPF programs that start with `mmap`. Both of these programs would be picked up. Tracee would first check if it can load `mmap_fentry`, if it couldn't (i.e. doesn't support BPF_PROG_TYPE_TRACING), it would check and then select `mmap_kprobe`. This selection process would be hidden from the user.

On startup, tracee would collect all programs in the bpf object. It would organize them by what events they produce. Then, for each event that the user has selected for tracee to produce, a program will be selected based on what program types are available for the running kernel. 

## Running instructions

`make` && `sudo ./main-static mmap`

the "mmap" argument represents the user specificying to trace the mmap call.
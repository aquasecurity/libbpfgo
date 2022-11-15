# multiple-objects

This selftest demonstrates having multiple bpf objects which each have
programs which rely on a single ringbuffer.

This is accomplished via map pinning. See the ringbuffer definition:

```C
struct {
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```

The `LIBBPF_PIN_BY_NAME` attribute instructs libbpf to pin the map to
a file in the bpf file system. When subsequent bpf maps are loaded by
libbpf with the same name/attribute, libbpf will automatically reuse
the file descriptor and wire it up as the same underly map.

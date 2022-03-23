package main

import "C"

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	bpf "github.com/aquasecurity/libbpfgo"
)

/*
	CreateMap uses `bpf_map_create()`, a 'low-level' API in libbpf
	As such, it does not have access to the higher level APIs in
	libbpf, which are denoted by starting with `bpf_map__*`.

	As such, you can use bpf_map_create() to populate arrays of maps
	in userspace, then iterate over those arrays on the bpf side, and
	use them as a normal map there as those operations only require
	a file descriptor.

	You can update values in the map from userspace, but currently
	can't retrieve values outright.

	For example:
	https://elixir.bootlin.com/linux/latest/source/samples/bpf/fds_example.c
	https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/test_maps.c
	https://lore.kernel.org/bpf/CAO658oWagXsQDeFtRA2vZBzov7cwwVNTs5nHE9fMGrMOs6bbpQ@mail.gmail.com/
*/

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	opts := bpf.BPFMapCreateOpts{}
	opts.Size = uint64(unsafe.Sizeof(opts))

	m, err := libbpfgo.CreateMap(libbpfgo.MapTypeHash, "foobar", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	key1 := uint32(1)
	value1 := uint32(55)
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1)
	err = m.Update(key1Unsafe, value1Unsafe)
	if err != nil {
		log.Fatal(err)
	}
}

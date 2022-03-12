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

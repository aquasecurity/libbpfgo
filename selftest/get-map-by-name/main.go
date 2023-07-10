package main

import "C"

import (
	"fmt"
	"os"
	"unsafe"

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

	testMap, err := bpf.GetMapByName("test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	key1 := uint32(1)
	value1 := uint32(55)
	if err := testMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value1)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

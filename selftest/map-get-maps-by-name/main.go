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

	testMaps := bpf.GetMapsByName("test")
	if len(testMaps) == 0 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("no maps found"))
		os.Exit(-1)
	}

	testMap := testMaps[0]
	key1 := uint32(0)
	value1 := uint32(55)
	if err := testMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value1)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

package main

import "C"

import (
	"fmt"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const BPFMapName = "test"

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	mapsIdS := bpf.GetMapsIdsByName(BPFMapName)
	if len(mapsIdS) == 0 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("no maps found for the %s map", BPFMapName))
		os.Exit(-1)
	}

	bpfMapId := mapsIdS[0]

	bpfMap, err := bpf.GetMapByID(bpfMapId)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("the %s map with %d id not found: %w", BPFMapName, bpfMapId, err))
		os.Exit(-1)
	}

	key1 := uint32(0)
	value1 := uint32(55)
	if err := bpfMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value1)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

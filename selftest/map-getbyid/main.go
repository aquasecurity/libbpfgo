package main

import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	// Get info about the "tester" map
	infoTester, err := bpf.GetMapInfoByFD(testerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}

	// Get a new BPFMapLow object pointing to the "tester" map
	testerMapLow, err := bpf.GetMapByID(infoTester.ID)
	if err != nil {
		common.Error(err)
	}

	if testerMapLow.Name() != testerMap.Name() {
		common.Error(errors.New("names do not match"))
	}
	if testerMapLow.Type() != testerMap.Type() {
		common.Error(errors.New("types do not match"))
	}
	if testerMapLow.MaxEntries() != testerMap.MaxEntries() {
		common.Error(errors.New("max entries do not match"))
	}
	if testerMapLow.KeySize() != testerMap.KeySize() {
		common.Error(errors.New("key sizes do not match"))
	}
	if testerMapLow.ValueSize() != testerMap.ValueSize() {
		common.Error(errors.New("value sizes do not match"))
	}

	// Save a value in the "tester" map using the original BPFMap object
	key1 := uint32(11)
	value1 := uint32(1917)
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1)
	err = testerMap.Update(key1Unsafe, value1Unsafe)
	if err != nil {
		common.Error(err)
	}

	// Get the value from the "tester" map using the new BPFMapLow object
	v, err := testerMapLow.GetValue(key1Unsafe)
	if err != nil {
		common.Error(err)
	}
	gotValue := common.ByteOrder().Uint32(v)
	if gotValue != value1 {
		common.Error(fmt.Errorf("value mismatch: %d != %d", gotValue, value1))
	}
}

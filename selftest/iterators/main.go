package main

import "C"

import (
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

const (
	iteratorMax uint32 = 5
	added       uint32 = 1
	checked     uint32 = 2
)

var one = 1

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()
	bpfModule.BPFLoadObject()

	numbers, err := bpfModule.GetMap("numbers")
	if err != nil {
		common.Error(err)
	}

	testMap := map[uint32]uint32{}
	var i uint32
	for i = 0; i < iteratorMax; i++ {
		testMap[i] = added
		index := unsafe.Pointer(&i)
		value := unsafe.Pointer(&one)
		err = numbers.Update(index, value)
		if err != nil {
			common.Error(err)
		}
	}

	iterator := numbers.Iterator()
	for iterator.Next() {
		keyBytes := iterator.Key()
		key := common.ByteOrder().Uint32(keyBytes)

		val, ok := testMap[key]
		if !ok {
			common.Error(fmt.Errorf("unknown key was found: %d", key))
		}
		if val != 1 {
			common.Error(fmt.Errorf("corrupted value: %d", val))
		}
		testMap[key] = checked
	}
	if iterator.Err() != nil {
		common.Error(fmt.Errorf("iterator error: %v", iterator.Err()))
	}

	// make sure it got everything
	for k, v := range testMap {
		if v != 2 {
			common.Error(fmt.Errorf("key was not found: %d", k))
		}
	}
}

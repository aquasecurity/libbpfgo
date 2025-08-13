package main

// #include "main.bpf.h"
import "C"

import (
	"bytes"
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

	testerReusedMap, err := bpfModule.GetMap("tester_reused")
	if err != nil {
		common.Error(err)
	}

	//
	// BPFMap ReuseFD
	//

	// The current instance of "tester_reused" will be closed, and testerReusedMap
	// will now point to the same map as testerMap "tester", however, via a
	// different FD.
	err = testerReusedMap.ReuseFD(testerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}

	if err != nil {
		common.Error(err)
	}

	valueSize := C.sizeof_struct_value

	key1 := uint32(1)
	value1 := make([]byte, valueSize)
	value1[0] = '7'
	value1[1] = '1'
	value1[2] = '9'
	value1[3] = '1'
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1[0])
	err = testerMap.Update(key1Unsafe, value1Unsafe) // update "tester"
	if err != nil {
		common.Error(err)
	}

	key2 := int32(42069420)
	value2 := make([]byte, valueSize)
	value2[0] = '1'
	value2[1] = '1'
	value2[2] = '0'
	value2[3] = '7'
	key2Unsafe := unsafe.Pointer(&key2)
	value2Unsafe := unsafe.Pointer(&value2[0])
	err = testerReusedMap.Update(key2Unsafe, value2Unsafe) // also update "tester"
	if err != nil {
		common.Error(err)
	}

	//
	// BPFMapLow ReuseFD
	//

	toReuseCreated, err := bpf.CreateMap(bpf.MapTypeArray, "toreuse", 4, 4, 420, nil)
	if err != nil {
		common.Error(err)
	}

	// The current instance of "toreuse" will be closed, and toReuseCreated
	// will now point to the same map as testerMap "tester", however, via a
	// different FD.
	err = toReuseCreated.ReuseFD(testerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}

	val2, err := toReuseCreated.GetValue(key2Unsafe) // lookup "tester"
	if err != nil {
		common.Error(err)
	}

	if !bytes.Equal(val2, value2) {
		common.Error(fmt.Errorf("expected value %s, got %s", value2, val2))
	}
}

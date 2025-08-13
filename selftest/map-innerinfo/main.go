package main

import "C"

import (
	"errors"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	outerHash, err := bpfModule.GetMap("outer_hash")
	if err != nil {
		common.Error(err)
	}

	// Retrieve an inner map prototype information from the outer map.
	innerInfo, err := outerHash.InnerMapInfo()
	if err != nil {
		common.Error(err)
	}

	if innerInfo.Name != "outer_hash.inner" {
		common.Error(fmt.Errorf("inner prototype name should be 'outer_hash.inner': %s", innerInfo.Name))
	}
	if innerInfo.Type != bpf.MapTypeArray {
		common.Error(fmt.Errorf("inner prototype type should be MapTypeArray: %s", innerInfo.Type))
	}
	if innerInfo.MaxEntries != 1 {
		common.Error(fmt.Errorf("inner prototype max entries should be 1: %d", innerInfo.MaxEntries))
	}
	if innerInfo.KeySize != 4 {
		common.Error(fmt.Errorf("inner prototype key size should be 4: %d", innerInfo.KeySize))
	}
	if innerInfo.ValueSize != 4 {
		common.Error(fmt.Errorf("inner prototype value size should be 4: %d", innerInfo.ValueSize))
	}
	if innerInfo.MapFlags != 0 {
		common.Error(fmt.Errorf("inner prototype map flags should be 0: %d", innerInfo.MapFlags))
	}
	if innerInfo.IfIndex != 0 {
		common.Error(fmt.Errorf("inner prototype ifindex should be 0: %d", innerInfo.IfIndex))
	}
	if innerInfo.MapExtra != 0 {
		common.Error(fmt.Errorf("inner prototype map extra should be 0: %d", innerInfo.MapExtra))
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	// Attempting to get inner map prototype information after the
	// object is loaded will fail.
	_, err = outerHash.InnerMapInfo()
	if err == nil {
		common.Error(errors.New("should fail to get inner map info after object is loaded"))
	}
}

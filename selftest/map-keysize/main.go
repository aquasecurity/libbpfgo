package main

import "C"

import (
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

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	keySize := testerMap.KeySize()
	if keySize != 4 {
		common.Error(fmt.Errorf("keySize do not match, expected 4, got %d", keySize))
	}

	err = testerMap.SetKeySize(8)
	if err != nil {
		common.Error(err)
	}

	keySize = testerMap.KeySize()
	if keySize != 8 {
		common.Error(fmt.Errorf("keySize do not match, expected 8, got %d", keySize))
	}

	bpfModule.BPFLoadObject()
}

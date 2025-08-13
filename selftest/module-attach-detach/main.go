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

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	// attach all programs
	err = bpfModule.AttachPrograms()
	if err != nil {
		common.Error(fmt.Errorf("attach programs failed: %s", err))
	}

	// detach all programs
	err = bpfModule.DetachPrograms()
	if err != nil {
		common.Error(fmt.Errorf("detach programs failed: %s", err))
	}
}

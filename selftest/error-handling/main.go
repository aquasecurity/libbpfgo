package main

import "C"

import (
	"errors"
	"syscall"

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

	bpfModule.BPFLoadObject()

	// non-existant program
	_, err = bpfModule.GetProgram("NewYorkYankeesRule")
	if err == nil {
		common.Error(errors.New("undetected error, non-existant program"))
	}
	if !errors.Is(err, syscall.ENOENT) {
		common.Error(fmt.Errorf("unexpected wrapped error received, expected ENOENT: %w", err))
	}

	// non-existant map
	_, err = bpfModule.GetMap("Ih8BostonRedSox")
	if err == nil {
		common.Error(errors.New("undetected error, non-existant map"))
	}
	if !errors.Is(err, syscall.ENOENT) {
		common.Error(fmt.Errorf("unexpected wrapped error received, expected ENOENT: %w", err))
	}

	// invalid tc hook
	tchook := bpfModule.TcHookInit()
	err = tchook.Create()
	if err == nil {
		common.Error(errors.New("undetected error, invalid tchook create arguments"))
	}
	if !errors.Is(err, syscall.EINVAL) {
		common.Error(fmt.Errorf("unexpected wrapped error received, expected EINVAL: %w", err))
	}
}

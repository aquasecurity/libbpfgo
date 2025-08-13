package main

import "C"

import (
	"errors"
	"syscall"

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

	templateInnerMap, err := bpf.CreateMap(bpf.MapTypeHash, "template_inner_map", 4, 4, 420, nil)
	if err != nil {
		common.Error(err)
	}

	// As the "outer_hash" map does not have an inner map prototype pre-allocated,
	// an active map (from any origin) must be used as a template, by calling
	// SetInnerMap() before the object is loaded, otherwise the BPF program will
	// fail to load. The template map can be removed after the object is loaded.
	err = outerHash.SetInnerMap(templateInnerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	//
	// "outer_hash" map of maps is now fully loaded and can be used.
	//

	// Attempting to set inner map after the object is loaded will fail.
	err = outerHash.SetInnerMap(templateInnerMap.FileDescriptor())
	if err == nil {
		common.Error(errors.New("should fail after object is loaded"))
	}

	// If not needed anymore, remove the "template_inner_map",
	// freeing up resources.
	err = syscall.Close(templateInnerMap.FileDescriptor())
	if err != nil {
		common.Error(err)
	}
}

package main

import "C"

import (
	"errors"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModuleWithAutocreate, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModuleWithAutocreate.Close()

	testerMapWithAutocreate, err := bpfModuleWithAutocreate.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	isAutocreate := testerMapWithAutocreate.Autocreate()
	if !isAutocreate {
		common.Error(errors.New("autocreate is false"))
	}

	err = bpfModuleWithAutocreate.BPFLoadObject()
	if err == nil {
		common.Error(errors.New("was able to load with a bad type of map"))
	}

	bpfModuleWithoutAutocreate, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModuleWithoutAutocreate.Close()

	testerMapWithoutAutocreate, err := bpfModuleWithoutAutocreate.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	err = testerMapWithoutAutocreate.SetAutocreate(false)
	if err != nil {
		common.Error(err)
	}

	isAutocreate = testerMapWithoutAutocreate.Autocreate()
	if isAutocreate {
		common.Error(errors.New("autocreate is true, expected false"))
	}

	err = bpfModuleWithoutAutocreate.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}
}

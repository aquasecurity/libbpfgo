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

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	iterator := bpfModule.Iterator()

	// Iterate over programs
	expectedProgramNames := map[string]bool{
		"mmap_fentry":     false,
		"execve_fentry":   false,
		"execveat_fentry": false,
	}

	currentProg := iterator.NextProgram()
	for currentProg != nil {
		expectedProgramNames[currentProg.GetName()] = true
		currentProg = iterator.NextProgram()
	}

	if len(expectedProgramNames) != 3 {
		common.Error(errors.New("did not iterate over expected programs"))
	}
	for k, v := range expectedProgramNames {
		if !v {
			common.Error(fmt.Errorf("did not iterate over expected program: %s", k))
		}
	}

	// Iterate over maps
	expectedMapNames := map[string]bool{
		"one": false,
		"two": false,
	}

	currentMap := iterator.NextMap()
	for currentMap != nil {
		expectedMapNames[currentMap.GetName()] = true
		currentMap = iterator.NextMap()
	}

	if len(expectedMapNames) != 2 {
		common.Error(errors.New("did not iterate over expected maps"))
	}
	for k, v := range expectedMapNames {
		if !v {
			common.Error(fmt.Errorf("did not iterate over expected map: %s", k))
		}
	}
}

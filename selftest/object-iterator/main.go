package main

import "C"

import (
	"os"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
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
		fmt.Fprintln(os.Stderr, "did not iterate over expected programs")
		os.Exit(-1)
	}
	for k, v := range expectedProgramNames {
		if v == false {
			fmt.Fprintf(os.Stderr, "did not iterate over expected program: %s", k)
			os.Exit(-1)
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
		fmt.Fprintln(os.Stderr, "did not iterate over expected maps")
		os.Exit(-1)
	}
	for k, v := range expectedMapNames {
		if v == false {
			fmt.Fprintf(os.Stderr, "did not iterate over expected map: %s", k)
			os.Exit(-1)
		}
	}
}

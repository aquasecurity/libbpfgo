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

	expectedNames := map[string]bool{
		"mmap_fentry":     false,
		"execve_fentry":   false,
		"execveat_fentry": false,
	}

	iterator := bpfModule.ProgramIterator()
	currentProg := iterator.Next()
	for currentProg != nil {
		expectedNames[currentProg.GetName()] = true
		currentProg = iterator.Next()
	}

	if len(expectedNames) != 3 {
		fmt.Fprintln(os.Stderr, "did not iterate over expected programs")
		os.Exit(-1)

	}
	for k, v := range expectedNames {
		if v == false {
			fmt.Fprintln(os.Stderr, "did not iterate over expected program: %s", k)
			os.Exit(-1)
		}
	}

}

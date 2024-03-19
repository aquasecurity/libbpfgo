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

	// attach all programs
	err = bpfModule.AttachPrograms()
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("attach programs failed: %s", err))
		os.Exit(-1)
	}

	// detach all programs
	err = bpfModule.DetachPrograms()
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("detach programs failed: %s", err))
		os.Exit(-1)
	}
}

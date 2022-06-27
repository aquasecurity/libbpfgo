package main

import "C"

import (
	"os"

	"fmt"

	"github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := libbpfgo.NewModuleFromFile("main.bpf.o")
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

	prog1, err := bpfModule.GetProgram("commit_creds")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	link1, err := prog1.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link1.GetFd() == 0 {
		os.Exit(-1)
	}

	fmt.Println(prog1.GetType().String())
}

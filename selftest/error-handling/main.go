package main

import "C"

import (
	"errors"
	"os"
	"syscall"

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

	bpfModule.BPFLoadObject()

	// non-existant program
	_, err = bpfModule.GetProgram("NewYorkYankeesRule")
	if err == nil {
		fmt.Fprintln(os.Stderr, "undetected error, non-existant program")
		os.Exit(-1)
	}
	if !errors.Is(err, syscall.ENOENT) {
		fmt.Fprintf(os.Stderr, "unexpected wrapped error received, expected ENOENT\n")
		os.Exit(-1)
	}

	// non-existant map
	_, err = bpfModule.GetMap("Ih8BostonRedSox")
	if err == nil {
		fmt.Fprintln(os.Stderr, "undetected error, non-existant map")
		os.Exit(-1)
	}
	if !errors.Is(err, syscall.ENOENT) {
		fmt.Fprintf(os.Stderr, "unexpected wrapped error received, expected ENOENT\n")
		os.Exit(-1)
	}

	// invalid tc hook
	tchook := bpfModule.TcHookInit()
	err = tchook.Create()
	if err == nil {
		fmt.Fprintln(os.Stderr, "undetected error, invalid tchook create arguments")
		os.Exit(-1)
	}
	if !errors.Is(err, syscall.EINVAL) {
		fmt.Fprintf(os.Stderr, "unexpected wrapped error received, expected EINVAL\n")
		os.Exit(-1)
	}
}

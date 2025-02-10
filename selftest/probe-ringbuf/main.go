package main

import "C"

import (
	"fmt"
	"os"

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

	// Should be supported from 5.8 onwards
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err != nil || !isSupported {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel1 := make(chan []byte)
	_, err = bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

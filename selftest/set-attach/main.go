package main

import "C"

import (
	"encoding/binary"
	"os"
	"syscall"
	"time"

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

	prog, err := bpfModule.GetProgram("foobar")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// eBPF program type should only be set if it differs from the desired one
	// commit d6e6286a12e7 ("libbpf: disassociate section handler on explicit bpf_program__set_type() call")
	// prog.SetProgramType(bpf.BPFProgTypeTracing)
	prog.SetAttachType(bpf.BPFAttachTypeTraceFentry)

	err = prog.SetAttachTarget(0, "__x64_sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	_, err = prog.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Second / 100)
		}
	}()
recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}
	rb.Stop()
	rb.Close()
}

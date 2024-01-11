package main

import "C"

import (
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"time"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
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

	m, err := helpers.NewKernelSymbolTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", ksymArch())
	sym, err := m.GetSymbolByName(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if sym[0].Address == 0 && sym[0].Name == "" {
		fmt.Fprintln(os.Stderr, "could not find symbol to attach to")
		os.Exit(-1)
	}

	prog, err := bpfModule.GetProgram("mmap_fentry")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	link, err := prog.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link.GetFd() == 0 {
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

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}

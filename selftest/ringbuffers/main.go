package main

import "C"

import (
	"os"
	"runtime"
	"syscall"
	"time"

	"encoding/binary"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events1", 8192); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", ksymArch())
	_, err = prog.AttachKprobe(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel1 := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel2 := make(chan []byte)
	ret, err := bpfModule.AddRingBuf(rb, "events2", eventsChannel2)
	if !ret {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(300)

	numberOfEvent1Received := 0
	numberOfEvent2Received := 0
	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Second / 2)
		}
	}()

recvLoop:
	for {
		select {
		case b := <-eventsChannel1:
			if binary.LittleEndian.Uint32(b) != 2021 {
				fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
				os.Exit(-1)
			}
			numberOfEvent1Received++
			if numberOfEvent1Received > 5 && numberOfEvent2Received > 5 {
				break recvLoop
			}
		case b := <-eventsChannel2:
			if binary.LittleEndian.Uint32(b) != 2024 {
				fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
				os.Exit(-1)
			}
			numberOfEvent2Received++
			if numberOfEvent1Received > 5 && numberOfEvent2Received > 5 {
				break recvLoop
			}
		}
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	rb.Stop()
	rb.Stop()
	rb.Close()
	rb.Close()
	rb.Stop()
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

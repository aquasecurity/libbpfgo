package main

import "C"

import (
	"encoding/binary"
	"os"
	"os/exec"
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

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	hook := bpfModule.TcHookInit()
	defer func() {
		if err := hook.Destroy(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	err = hook.SetInterfaceByName("lo")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to set tc hook on interface lo: %v", err)
		os.Exit(-1)
	}

	hook.SetAttachPoint(bpf.BPFTcEgress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			fmt.Fprintln(os.Stderr, "tc hook create: %v", err)
		}
	}

	tcProg, err := bpfModule.GetProgram("target")
	if tcProg == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	var tcOpts bpf.TcOpts // https://elixir.bootlin.com/linux/v6.8.4/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L26
	tcOpts.ProgFd = int(tcProg.GetFd())
	tcOpts.Handle = 1
	tcOpts.Priority = 1
	err = hook.Attach(&tcOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// test for query
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	err = hook.Query(&tcOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if tcOpts.Handle != 1 {
		fmt.Fprintln(os.Stderr, "query info error, handle:%d", tcOpts.Handle)
		os.Exit(-1)
	}

	// test for detach
	defer func() {
		tcOpts.ProgFd = 0
		tcOpts.ProgId = 0
		err = hook.Detach(&tcOpts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		_, err := exec.Command("ping", "localhost", "-c 10").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
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

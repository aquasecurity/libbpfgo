package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	deviceName = "lo"
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

	xdpProg, err := bpfModule.GetProgram("target")
	if xdpProg == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = xdpProg.AttachXDP(deviceName)
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

	rb.Start()
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

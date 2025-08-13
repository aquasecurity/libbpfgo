package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"os/exec"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

const (
	deviceName = "lo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	xdpProg, err := bpfModule.GetProgram("target")
	if xdpProg == nil {
		common.Error(err)
	}

	err = xdpProg.AttachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	if err != nil {
		common.Error(err)
	}
	err = xdpProg.DetachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	if err != nil {
		common.Error(err)
	}

	_, err = xdpProg.AttachXDP(deviceName)
	if err != nil {
		common.Error(err)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(err)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		_, err := exec.Command("ping", "localhost", "-c 10").Output()
		if err != nil {
			common.Error(err)
		}
	}()

recvLoop:

	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			common.Error(fmt.Errorf("invalid data retrieved: %v", b))
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
}

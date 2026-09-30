package main

import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

const (
	deviceName        = "lo"
	missingDeviceName = "libbpfgo-no-such-dev"
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

	tcxProg, err := bpfModule.GetProgram("target")
	if tcxProg == nil {
		common.Error(err)
	}

	// attaching to an unknown device must fail instead of panicking
	if _, err := tcxProg.AttachTCX(missingDeviceName); err == nil {
		common.Error(fmt.Errorf("attaching tcx to %s should have failed", missingDeviceName))
	}

	link, err := tcxProg.AttachTCX(deviceName)
	if err != nil {
		common.Error(err)
	}
	if link.FileDescriptor() < 0 {
		common.Error(errors.New("tcx link has an invalid file descriptor"))
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

	// the link must be detachable on its own, before the module is closed
	if err := link.Destroy(); err != nil {
		common.Error(err)
	}
}

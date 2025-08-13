package main

import "C"

import (
	"encoding/binary"
	"errors"
	"syscall"
	"time"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	prog, err := bpfModule.GetProgram("foobar")
	if err != nil {
		common.Error(err)
	}

	// eBPF program type should only be set if it differs from the desired one
	// commit d6e6286a12e7 ("libbpf: disassociate section handler on explicit bpf_program__set_type() call")
	// err = prog.SetType(bpf.BPFProgTypeTracing)
	// if err != nil {
	//	 common.Error(err)
	// }
	err = prog.SetExpectedAttachType(bpf.BPFAttachTypeTraceFentry)
	if err != nil {
		common.Error(err)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())
	err = prog.SetAttachTarget(0, funcName)
	if err != nil {
		common.Error(err)
	}

	// Test auto attach
	autoAttachOrig := prog.Autoattach()
	prog.SetAutoattach(!autoAttachOrig)
	if prog.Autoattach() == autoAttachOrig {
		common.Error(errors.New("set auto attach failed"))
	}
	prog.SetAutoattach(autoAttachOrig)

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}
	_, err = prog.AttachGeneric()
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
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Second / 100)
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

package main

import "C"

import (
	"encoding/binary"
	"errors"
	"syscall"
	"time"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/libbpfgo/selftest/common"
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

	m, err := helpers.NewKernelSymbolTable()
	if err != nil {
		common.Error(err)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())
	sym, err := m.GetSymbolByName(funcName)
	if err != nil {
		common.Error(err)
	}

	if sym[0].Address == 0 && sym[0].Name == "" {
		common.Error(errors.New("could not find symbol to attach to"))
	}

	prog, err := bpfModule.GetProgram("mmap_fentry")
	if err != nil {
		common.Error(err)
	}
	link, err := prog.AttachGeneric()
	if err != nil {
		common.Error(err)
	}
	if link.GetFd() == 0 {
		common.Error(errors.New("failed to attach program"))
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

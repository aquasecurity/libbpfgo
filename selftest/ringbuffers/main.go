package main

import "C"

import (
	"syscall"
	"time"

	"encoding/binary"
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

	if err = common.ResizeMap(bpfModule, "events1", 8192); err != nil {
		common.Error(err)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		common.Error(err)
	}

	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())
	_, err = prog.AttachKprobe(funcName)
	if err != nil {
		common.Error(err)
	}

	eventsChannel1 := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		common.Error(err)
	}

	eventsChannel2 := make(chan []byte)
	ret, err := bpfModule.AddRingBuf(rb, "events2", eventsChannel2)
	if !ret {
		common.Error(err)
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
				common.Error(fmt.Errorf("invalid data retrieved: %v", b))
			}
			numberOfEvent1Received++
			if numberOfEvent1Received > 5 && numberOfEvent2Received > 5 {
				break recvLoop
			}
		case b := <-eventsChannel2:
			if binary.LittleEndian.Uint32(b) != 2024 {
				common.Error(fmt.Errorf("invalid data retrieved: %v", b))
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

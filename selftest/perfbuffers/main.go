package main

import "C"

import (
	"time"

	"encoding/binary"
	"fmt"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	if err = common.ResizeMap(bpfModule, "events", 8192); err != nil {
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

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		common.Error(err)
	}

	pb.Poll(300)

	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-stop:
				return
			case b := <-eventsChannel:
				if binary.LittleEndian.Uint32(b) != 2021 {
					common.Error(fmt.Errorf("invalid data retrieved: %v", b))
				}
			}
		}
	}()

	// give some time for the upper goroutine to start
	time.Sleep(100 * time.Millisecond)

	for sent := 0; sent < 5; sent++ {
		syscall.Mmap(999, 999, 999, 1, 1)
		time.Sleep(100 * time.Millisecond)
	}

	close(stop)

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	pb.Stop()
	pb.Stop()
	pb.Close()
	pb.Close()
	pb.Stop()
}

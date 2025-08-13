package main

import "C"

import (
	"errors"
	"log"
	"syscall"
	"time"
	"unsafe"

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

	if err = common.ResizeMap(bpfModule, "events", 8192); err != nil {
		common.Error(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	// bpfModule.ListProgramNames()

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

	lostEventCounterMap, err := bpfModule.GetMap("counter_hash_map")
	if err != nil {
		common.Error(err)
	}

	var lostEventCounterKey uint32 = 1
	var zero uint32
	lostEventCounterMap.Update(unsafe.Pointer(&lostEventCounterKey), unsafe.Pointer(&zero))

	rb.Poll(300)

	numberOfEventsReceived := 0
	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Second / 2)
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

	val, err := lostEventCounterMap.GetValue(unsafe.Pointer(&lostEventCounterKey))
	if err != nil {
		common.Error(err)
	}

	log.Printf("lost events = %d", binary.LittleEndian.Uint32(val))
}

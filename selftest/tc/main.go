package main

import "C"

import (
	"encoding/binary"
	"log"
	"os/exec"
	"syscall"

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

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	hook := bpfModule.TcHookInit()
	defer func() {
		if err := hook.Destroy(); err != nil {
			log.Printf("Failed to destroy tc hook: %v", err)
		}
	}()

	err = hook.SetInterfaceByName("lo")
	if err != nil {
		common.Error(fmt.Errorf("failed to set tc hook on interface lo: %v", err))
	}

	hook.SetAttachPoint(bpf.BPFTcEgress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			common.Error(fmt.Errorf("tc hook create: %v", err))
		}
	}

	tcProg, err := bpfModule.GetProgram("target")
	if tcProg == nil {
		common.Error(err)
	}

	var tcOpts bpf.TcOpts // https://elixir.bootlin.com/linux/v6.8.4/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L26
	tcOpts.ProgFd = int(tcProg.GetFd())
	tcOpts.Handle = 1
	tcOpts.Priority = 1
	err = hook.Attach(&tcOpts)
	if err != nil {
		common.Error(err)
	}

	// test for query
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	err = hook.Query(&tcOpts)
	if err != nil {
		common.Error(err)
	}
	if tcOpts.Handle != 1 {
		common.Error(fmt.Errorf("query info error, handle: %d", tcOpts.Handle))
	}

	// test for detach
	defer func() {
		tcOpts.ProgFd = 0
		tcOpts.ProgId = 0
		err = hook.Detach(&tcOpts)
		if err != nil {
			common.Error(err)
		}
	}()

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

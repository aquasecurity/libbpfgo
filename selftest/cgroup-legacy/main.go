package main

import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

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

	prog, err := bpfModule.GetProgram("cgroup__skb_ingress")
	if err != nil {
		common.Error(err)
	}

	cgroupRootDir, err := common.GetCgroupV2RootDir()
	if err != nil {
		common.Error(err)
	}

	// link, err := prog.AttachCgroup(cgroupRootDir)
	link, err := prog.AttachCgroupLegacy(cgroupRootDir, bpf.BPFAttachTypeCgroupInetIngress)
	if err != nil {
		common.Error(err)
	}

	eventsChannel := make(chan []byte, 1)
	lostChannel := make(chan uint64, 1)

	// initialize an eBPF perf buffer to receive events
	bpfPerfBuffer, err := bpfModule.InitPerfBuf(
		"perfbuffer", eventsChannel, lostChannel, 1,
	)
	if err != nil {
		common.Error(err)
	}

	// signal handling
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	// start eBPF perf buffer event polling
	bpfPerfBuffer.Poll(5000)

	go func() {
		_, err := exec.Command("ping", "127.0.0.1", "-c 5", "-w 10").Output()
		if err != nil {
			common.Error(err)
		}
		time.Sleep(time.Second)
		stop()
	}()

	testPassed := false
	numberOfEventsReceived := 0

LOOP:
	for {
		select {
		case raw := <-eventsChannel:

			value := int(binary.LittleEndian.Uint32(raw))
			if value == 20220823 {
				log.Println("Received correct event")
				numberOfEventsReceived++
				if numberOfEventsReceived >= 5 {
					testPassed = true
					break LOOP
				}
			}
		case <-ctx.Done():
			break LOOP
		}
	}

	err = link.Destroy()
	if err != nil {
		common.Error(err)
	}

	if !testPassed {
		common.Error(errors.New("unable to get all packets"))
	}
}

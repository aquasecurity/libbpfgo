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

	prog, err := bpfModule.GetProgram("cgroup__sock")
	if err != nil {
		common.Error(err)
	}

	cgroupRootDir, err := common.GetCgroupV2RootDir()
	if err != nil {
		common.Error(err)
	}
	link, err := prog.AttachCgroup(cgroupRootDir)
	if err != nil {
		common.Error(err)
	}
	if link.GetFd() == 0 {
		common.Error(errors.New("failed to attach cgroup"))
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(err)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		for i := 0; i < 10; i++ {
			_, err := exec.Command("ping", "localhost", "-c 1", "-w 1").Output()
			if err != nil {
				common.Error(err)
			}
		}
	}()

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			common.Error(fmt.Errorf("invalid data retrieved: %s", b))
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
}

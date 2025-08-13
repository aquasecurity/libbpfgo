package main

import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

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

	prog, err := bpfModule.GetProgram("sk_lookup__lookup")
	if err != nil {
		common.Error(err)
	}

	link, err := prog.AttachNetns("/proc/self/ns/net")
	if err != nil {
		common.Error(err)
	}
	if link.GetFd() == 0 {
		common.Error(errors.New("fd is 0"))
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(err)
	}

	rb.Poll(300)
	numberOfEventsReceived := 0
	go func() {
		l, err := net.Listen("tcp", "127.0.0.1:")
		if err != nil {
			common.Error(err)
		}
		go func() {
			for {
				l.Accept()
			}
		}()
		for i := 0; i < 10; i++ {
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				common.Error(err)
			}
			c.Write([]byte{0})
			c.Close()
		}
	}()

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			common.Error(fmt.Errorf("invalid event data: %v", b))
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()
}

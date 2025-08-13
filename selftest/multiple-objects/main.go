package main

import "C"

import (
	"encoding/binary"
	"errors"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	mapModule, err := bpf.NewModuleFromFile("map.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer mapModule.Close()

	firstModule, err := bpf.NewModuleFromFile("first.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer firstModule.Close()

	secondModule, err := bpf.NewModuleFromFile("second.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer secondModule.Close()

	err = mapModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}
	err = firstModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}
	err = secondModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	firstProgram, err := firstModule.GetProgram("openat_fentry")
	if err != nil {
		common.Error(fmt.Errorf("couldn't get program1 %s", err))
	}

	link1, err := firstProgram.AttachGeneric()
	if err != nil {
		common.Error(fmt.Errorf("couldn't attach prog1 %s", err))
	}
	if link1.GetFd() == 0 {
		common.Error(errors.New("link1 fd is 0"))
	}

	secondProgram, err := secondModule.GetProgram("mmap_fentry")
	if err != nil {
		common.Error(fmt.Errorf("couldn't get program2 %s", err))
	}

	link2, err := secondProgram.AttachGeneric()
	if err != nil {
		common.Error(fmt.Errorf("couldn't attach program2 %s", err))
	}
	if link2.GetFd() == 0 {
		common.Error(errors.New("link2 fd is 0"))
	}

	eventsChannel := make(chan []byte)
	ringBuf, err := mapModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		common.Error(fmt.Errorf("couldn't init ringbuffer %s", err))
	}
	ringBuf.Poll(300)
	gotOne, gotTwo := false, false

thisloop:
	for {
		b := <-eventsChannel
		switch binary.LittleEndian.Uint32(b) {
		case 1:
			gotOne = true
			if gotTwo {
				break thisloop
			}
		case 2:
			gotTwo = true
			if gotOne {
				break thisloop
			}
		default:
			common.Error(fmt.Errorf("got invalid event %d", binary.LittleEndian.Uint32(b)))
		}
	}
}

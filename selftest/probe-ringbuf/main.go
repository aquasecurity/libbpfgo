package main

import "C"

import (
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

	// Should be supported from 5.8 onwards
	isSupported, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeRingbuf)
	if err != nil || !isSupported {
		common.Error(err)
	}

	eventsChannel1 := make(chan []byte)
	_, err = bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		common.Error(err)
	}
}

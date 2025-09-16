package main

import "C"

import (
	"errors"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	kernelVersion := common.GetKernelVersion()
	kernelRelease := common.GetKernelRelease()
	log.Printf("Running on kernel: %s", kernelVersion)
	log.Printf("Kernel release: %s", kernelRelease)

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

	log.Printf("BPFMapTypeIsSupported(MapTypeRingbuf) returned: isSupported=%v, err=%v", isSupported, err)

	if err != nil {
		common.Error(err)
	}
	if !isSupported {
		common.Error(errors.New("ringbuf is not supported on this kernel (expected supported from 5.8 onwards)"))
	}

	log.Println("Ringbuf is supported as expected")

	eventsChannel1 := make(chan []byte)
	_, err = bpfModule.InitRingBuf("events1", eventsChannel1)
	if err != nil {
		common.Error(err)
	}
}

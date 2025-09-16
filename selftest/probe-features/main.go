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

	kprobeProg, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		common.Error(err)
	}

	err = kprobeProg.SetAutoload(false)
	if err != nil {
		common.Error(err)
	}

	isSupported, err := bpf.BPFProgramTypeIsSupported(bpf.BPFProgTypeKprobe)
	log.Printf("BPFProgramTypeIsSupported(BPFProgTypeKprobe) returned: isSupported=%v, err=%v", isSupported, err)
	if err != nil {
		common.Error(err)
	}

	if isSupported {
		err = kprobeProg.SetAutoload(true)
		if err != nil {
			common.Error(err)
		}
	}

	// Test auto load result
	autoLoadOrig := kprobeProg.Autoload()
	kprobeProg.SetAutoload((!autoLoadOrig))
	if kprobeProg.Autoload() == autoLoadOrig {
		common.Error(errors.New("auto load result not changed"))
	}
	kprobeProg.SetAutoload((autoLoadOrig))

	err = bpfModule.BPFLoadObject()
	if err != nil {
		common.Error(err)
	}

	isSupported, err = bpf.BPFMapTypeIsSupported(bpf.MapTypeHash)
	log.Printf("BPFMapTypeIsSupported(MapTypeHash) returned: isSupported=%v, err=%v", isSupported, err)
	if err != nil {
		common.Error(err)
	}

	if isSupported {
		_, err = bpf.CreateMap(bpf.MapTypeHash, "foobar", 4, 4, 420, nil)
		if err != nil {
			common.Error(err)
		}
	}
}

package main

import "C"

import (
	"fmt"
	"log"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())

	funcAddr, err := common.KernelSymbolToAddr(funcName, true)
	if err != nil {
		common.Error(err)
	}
	if funcAddr == 0 {
		common.Error(fmt.Errorf("symbol %s found but has address 0", funcName))
	}

	log.Printf("Found symbol %s at address 0x%x", funcName, funcAddr)

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		common.Error(err)
	}

	_, err = prog.AttachKprobeOffset(funcAddr)
	if err != nil {
		common.Error(err)
	}

	go func() {
		time.Sleep(time.Second)
		syscall.Mmap(999, 999, 999, 1, 1)
		syscall.Mmap(999, 999, 999, 1, 1)
	}()

	time.Sleep(time.Second * 2)
}

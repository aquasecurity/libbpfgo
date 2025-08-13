package main

import "C"

import (
	"time"

	"fmt"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())

	kst, err := helpers.NewKernelSymbolTable()
	if err != nil {
		common.Error(err)
	}

	funcSymbol, err := kst.GetSymbolByName(funcName)
	if err != nil {
		common.Error(err)
	}

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

	_, err = prog.AttachKprobeOffset(funcSymbol[0].Address)
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

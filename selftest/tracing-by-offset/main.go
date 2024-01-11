package main

import "C"

import (
	"os"
	"runtime"
	"time"

	"fmt"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

func main() {
	funcName := fmt.Sprintf("__%s_sys_mmap", ksymArch())

	kst, err := helpers.NewKernelSymbolTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewKernelSymbolTable() failed: %v", err)
		os.Exit(-1)
	}

	funcSymbol, err := kst.GetSymbolByName(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Expected to find symbol %s, but it was not found", funcSymbol)
		os.Exit(-1)
	}

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachKprobeOffset(funcSymbol[0].Address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	go func() {
		time.Sleep(time.Second)
		syscall.Mmap(999, 999, 999, 1, 1)
		syscall.Mmap(999, 999, 999, 1, 1)
	}()

	time.Sleep(time.Second * 2)
}

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}

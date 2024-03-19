package main

import "C"

import (
	"fmt"
	"log"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	kprobeProg, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = kprobeProg.SetAutoload(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	isSupported, err := bpf.BPFProgramTypeIsSupported(bpf.BPFProgTypeKprobe)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if isSupported {
		err = kprobeProg.SetAutoload(true)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}

	// Test auto load result
	autoLoadOrig := kprobeProg.Autoload()
	kprobeProg.SetAutoload((!autoLoadOrig))
	if kprobeProg.Autoload() == autoLoadOrig {
		fmt.Println(os.Stderr, "auto load result wrong")
		os.Exit(-1)
	}
	kprobeProg.SetAutoload((autoLoadOrig))

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	isSupported, err = bpf.BPFMapTypeIsSupported(bpf.MapTypeHash)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if isSupported {
		_, err = bpf.CreateMap(bpf.MapTypeHash, "foobar", 4, 4, 420, nil)
		if err != nil {
			log.Fatal(err)
		}
	}
}

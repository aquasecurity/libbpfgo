package main

import "C"

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.ListProgramNames()

	prog, err := bpfModule.GetProgram("mmap_fentry")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	lostEventCounterMap, err := bpfModule.GetMap("percpu_hash")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	link, err := prog.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link.GetFd() == 0 {
		os.Exit(-1)
	}

	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Millisecond * 30)
		}
	}()

	// all values regardless of size are rounded up to 8 for struct
	// padding in PERCPU maps
	valueSize := 8 * runtime.NumCPU()
	fmt.Println(valueSize)
	err = lostEventCounterMap.SetValueSize(uint32(valueSize))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	time.Sleep(time.Second * 2)
	key := 0
	val, err := lostEventCounterMap.GetValue(unsafe.Pointer(&key))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	last := 0
	fmt.Println("len", len(val))
	for i := 0; i < runtime.NumCPU(); i++ {
		fmt.Println((val[last : last+8]))
		last += 8
	}

	time.Sleep(time.Minute)
}

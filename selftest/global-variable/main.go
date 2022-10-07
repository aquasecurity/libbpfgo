package main

import "C"
import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

func initGlobalVariable(bpfModule *bpf.Module, name string, value int) {
	bmap, err := bpfModule.GetMap(name)
	if err != nil {
		exitWithErr(err)
	}
	val := C.int(value)
	if err := bmap.SetInitialValue(unsafe.Pointer(&val)); err != nil {
		exitWithErr(err)
	}
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		exitWithErr(err)
	}
	defer bpfModule.Close()

	initGlobalVariable(bpfModule, ".rodata", 2000)
	initGlobalVariable(bpfModule, ".rodata.foo", 10)
	initGlobalVariable(bpfModule, ".rodata.bar", 8)
	initGlobalVariable(bpfModule, ".data.baz", 2)
	initGlobalVariable(bpfModule, ".data.qux", 1)

	if err := bpfModule.BPFLoadObject(); err != nil {
		exitWithErr(err)
	}

	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		exitWithErr(err)
	}

	if _, err := prog.AttachKprobe("__x64_sys_mmap"); err != nil {
		exitWithErr(err)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		exitWithErr(err)
	}

	rb.Start()
	go func() {
		time.Sleep(time.Second)
		syscall.Mmap(999, 999, 999, 1, 1)
	}()

	b := <-eventsChannel
	if binary.LittleEndian.Uint32(b) != 2021 {
		fmt.Fprintf(os.Stderr, "invalid data retrieved: %v\n", b)
		os.Exit(-1)
	}

	rb.Stop()
	rb.Close()
}

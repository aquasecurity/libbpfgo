package main

import "C"

import (
	"encoding/binary"
	"errors"
	"log"
	"runtime"
	"syscall"
	"time"
	"unsafe"

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

	prog, err := bpfModule.GetProgram("mmap_fentry")
	if err != nil {
		common.Error(err)
	}

	link, err := prog.AttachGeneric()
	if err != nil {
		common.Error(err)
	}
	if link.GetFd() == 0 {
		common.Error(errors.New("link fd is 0"))
	}

	go func() {
		for {
			syscall.Mmap(999, 999, 999, 1, 1)
			time.Sleep(time.Millisecond * 30)
		}
	}()

	lostEventCounterMap, err := bpfModule.GetMap("percpu_hash")
	if err != nil {
		common.Error(err)
	}

	time.Sleep(time.Second * 2)
	key := 0
	values := make([]byte, 8*runtime.NumCPU())
	err = lostEventCounterMap.GetValueReadInto(unsafe.Pointer(&key), &values)
	if err != nil {
		common.Error(err)
	}

	last := 0
	for i := 0; i < runtime.NumCPU(); i++ {
		log.Printf("CPU %d: %d\n", i, binary.LittleEndian.Uint32(values[last:last+8]))
		last += 8
	}
}

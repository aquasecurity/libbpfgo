package main

import "C"

import (
	"errors"
	"time"
	"unsafe"

	"encoding/binary"
	"fmt"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	if err = common.ResizeMap(bpfModule, "events", 8192); err != nil {
		common.Error(err)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		common.Error(err)
	}

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		common.Error(err)
	}

	if testerMap.Name() != "tester" {
		common.Error(errors.New("wrong map name"))
	}

	if testerMap.Type() != bpf.MapTypeHash {
		common.Error(errors.New("wrong map type"))
	}

	key1 := uint32(1)
	value1 := struct{ x int }{50}
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1)
	testerMap.Update(key1Unsafe, value1Unsafe)

	key2 := int64(42069420)
	value2 := []byte{'a', 'b', 'c'}
	key2Unsafe := unsafe.Pointer(&key2)
	value2Unsafe := unsafe.Pointer(&value2[0])
	testerMap.Update(key2Unsafe, value2Unsafe)

	funcName := fmt.Sprintf("__%s_sys_mmap", common.KSymArch())
	_, err = prog.AttachKprobe(funcName)
	if err != nil {
		common.Error(err)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		common.Error(err)
	}

	pb.Poll(300)

	go func() {
		time.Sleep(time.Second)
		syscall.Mmap(999, 999, 999, 1, 1)
		syscall.Mmap(999, 999, 999, 1, 1)
	}()

	ev := <-eventsChannel
	if binary.LittleEndian.Uint32(ev) != 50 {
		common.Error(fmt.Errorf("invalid data retrieved: %v", ev))
	}

	ev = <-eventsChannel
	if ev[0] != value2[0] || ev[1] != value2[1] || ev[2] != value2[2] {
		common.Error(fmt.Errorf("invalid data retrieved: %v", ev))
	}

	pb.Stop()
	pb.Close()
}

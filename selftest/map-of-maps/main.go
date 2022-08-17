package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	bpf "github.com/aquasecurity/libbpfgo"
)

/*
	Interactions with hash of maps and array of map uses `CreateMap` and `GetMapByID`` which use
	`bpf_map_create()` and `bpf_map_get_fd_by_id()`, 'low-level' APIs in libbpf.
	As such, it does not have access to the higher level APIs in
	libbpf, which are denoted by starting with `bpf_map__*`.
*/

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	outerMap, err := bpfModule.GetMap("outer_map")
	if err != nil {
		log.Fatal(err)
	}

	outerArray, err := bpfModule.GetMap("outer_map")
	if err != nil {
		log.Fatal(err)
	}

	dummyInnerMap, err := libbpfgo.CreateMap(libbpfgo.MapTypeHash, "dummy_inner_map", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := outerMap.SetInnerMap(dummyInnerMap); err != nil {
		log.Fatal(err)
	}

	dummyInnerMapArr, err := libbpfgo.CreateMap(libbpfgo.MapTypeHash, "dummy_inner_map_array", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := outerArray.SetInnerMap(dummyInnerMapArr); err != nil {
		log.Fatal(err)
	}

	bpfModule.BPFLoadObject()
	opts := bpf.BPFMapCreateOpts{}
	opts.Size = uint64(unsafe.Sizeof(opts))

	// You have to close the inner map fd after insertion to avoid memory leak.
	// Because after map creation, you have a reference (fd) to the map in user space.
	// After insertion, kernel has a reference to the map in kernel space.
	// If you don’t close the map fd now, then after the entry is deleted from the outer map (kernel releases its reference),
	// the inner map resource won’t be cleaned up since you still have the reference even though you may have lost the fd after your insertion function returns.
	if err := syscall.Close(dummyInnerMap.GetFd()); err != nil {
		log.Fatal(err)
	}

	if err := syscall.Close(dummyInnerMapArr.GetFd()); err != nil {
		log.Fatal(err)
	}

	// Create an inner map.
	innerMap, err := libbpfgo.CreateMap(libbpfgo.MapTypeHash, "inner_map", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Insert into inner map.

	innerKey := uint32(1)
	innerValue := uint32(55)
	innerKeyUnsafe := unsafe.Pointer(&innerKey)
	innerValueUnsafe := unsafe.Pointer(&innerValue)
	if err := innerMap.Update(innerKeyUnsafe, innerValueUnsafe); err != nil {
		log.Fatal(err)
	}

	// Insert into outer map.

	outerKey := uint32(1)
	// The FD of the map needs to be passed as a pointer to the map.
	// It will be stored by its ID in the outer map.
	outerValue := innerMap.GetFd()
	outerKeyUnsafe := unsafe.Pointer(&outerKey)
	outerValueUnsafe := unsafe.Pointer(&outerValue)
	if err := outerMap.Update(outerKeyUnsafe, outerValueUnsafe); err != nil {
		log.Fatal(err)
	}

	// Read from outer and then inner map.

	val, err := outerMap.GetValue(outerKeyUnsafe)
	if err != nil {
		log.Fatal(err)
	}

	id := determineHostByteOrder().Uint32(val)
	readInnerMap, err := bpfModule.GetMapByID(id)
	if err != nil {
		log.Fatal(err)
	}

	inVal, err := readInnerMap.GetValue(innerKeyUnsafe)
	if err != nil {
		log.Fatal(err)
	}

	if determineHostByteOrder().Uint32(inVal) != innerValue {
		log.Fatal("Inner map value not equal to expected value.")
	}

	// Delete from outer map.

	if err := outerMap.DeleteKey(outerKeyUnsafe); err != nil {
		log.Fatal(err)
	}
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

package main

import "C"

import (
	"encoding/binary"
	"log"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	innerArray, err := bpf.CreateMap(bpf.MapTypeArray, "inner_array", 4, 4, 1, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create the "outer_hash" map, using the "inner_array" map as a prototype.
	opts := bpf.BPFMapCreateOpts{
		InnerMapFD: uint32(innerArray.FileDescriptor()),
	}
	outerHash, err := bpf.CreateMap(bpf.MapTypeHash, "outer_hash", 4, 4, 1, &opts)
	if err != nil {
		log.Fatal(err)
	}

	// Save the inner map in the "outer_hash" map, using the hash key 1917.
	// The value used to save the element is the the inner map file descriptor,
	// however the actual saved value is the inner map ID.
	key1 := uint32(1917)
	key1Unsafe := unsafe.Pointer(&key1)
	value1 := uint32(innerArray.FileDescriptor()) // "inner_array" FD.
	value1Unsafe := unsafe.Pointer(&value1)
	err = outerHash.Update(key1Unsafe, value1Unsafe)
	if err != nil {
		log.Fatal(err)
	}

	// Save an element in the "inner_array" map.
	key1 = uint32(0) // index 0
	value1 = uint32(191711)
	value1Unsafe = unsafe.Pointer(&value1)
	err = innerArray.Update(key1Unsafe, value1Unsafe)
	if err != nil {
		log.Fatal(err)
	}
}

func endian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

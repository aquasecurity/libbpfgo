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

	// Since the outer and inner map definitions are pre-allocated in the
	// BPF object, we do not need to do anything before loading the object.
	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	outerHash, err := bpfModule.GetMap("outer_hash")
	if err != nil {
		log.Fatal(err)
	}

	innerArray, err := bpfModule.GetMap("inner_array")
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the "inner_array" map ID from the "outer_hash" map,
	// using the hash key 1917.
	key1 := uint32(1917)
	key1Unsafe := unsafe.Pointer(&key1)
	innerMapIDBytes, err := outerHash.GetValue(key1Unsafe)
	if err != nil {
		log.Fatal(err)
	}

	// Inner map ID retrieved from the outer map element.
	innerMapID := endian().Uint32(innerMapIDBytes)

	// Retrieve the "inner_array" map Info.
	innerMapInfo, error := bpf.GetMapInfoByFD(innerArray.FileDescriptor())
	if error != nil {
		log.Fatal(error)
	}

	// Check if the inner map ID retrieved from the outer map matches the
	// inner map ID retrieved directly from the inner map.
	if innerMapInfo.ID != innerMapID {
		log.Fatal("inner map ID does not match")
	}

	// Save an element in the "inner_array" map.
	key1 = uint32(0) // index 0
	value1 := uint32(191711)
	value1Unsafe := unsafe.Pointer(&value1)
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

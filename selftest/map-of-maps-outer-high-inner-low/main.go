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

	outerHash, err := bpfModule.GetMap("outer_hash")
	if err != nil {
		log.Fatal(err)
	}

	innerArray, err := bpf.CreateMap(bpf.MapTypeArray, "inner_array", 4, 4, 1, nil)
	if err != nil {
		log.Fatal(err)
	}

	// As the "outer_hash" map does not have an inner map prototype pre-allocated,
	// an active map (from any origin) must be used as a template, by calling
	// SetInnerMap() before the object is loaded, otherwise the BPF program will
	// fail to load. The template map can be removed after the object is loaded.
	err = outerHash.SetInnerMap(innerArray.FileDescriptor())
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	// Save the inner map in the "outer_hash" map, using the hash key 1917.
	// The value used to save the element is the the inner map file descriptor,
	// however the actual saved value is the inner map ID.
	key := uint32(1917)
	keyUnsafe := unsafe.Pointer(&key)
	value := uint32(innerArray.FileDescriptor()) // "inner_array" FD.
	valueUnsafe := unsafe.Pointer(&value)
	err = outerHash.Update(keyUnsafe, valueUnsafe)
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the value of the previous saved element from the "outer_hash" map,
	// using the hash key 1917.
	key = uint32(1917)
	keyUnsafe = unsafe.Pointer(&key)
	innerMapIDBytes, err := outerHash.GetValue(keyUnsafe) // "inner_array" ID
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
	key = uint32(0) // index 0
	value = uint32(191711)
	err = innerArray.Update(keyUnsafe, valueUnsafe)
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

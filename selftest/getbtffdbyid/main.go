package main

import "C"

import (
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

	// Use the "inner_array_proto" map BTF ID to create a new map with the same
	// BTF type.
	innerArrayProto, err := bpfModule.GetMap("inner_array_proto")
	if err != nil {
		log.Fatal(err)
	}

	optsProto, err := bpf.GetMapInfoByFD(innerArrayProto.FileDescriptor())
	if err != nil {
		log.Fatal(err)
	}

	// The "inner_array_proto" map is a BTF map, so its ID can be used to create
	// a new map with the same BTF type.
	btfFD, err := bpf.GetBTFFDByID(optsProto.BTFID)
	if err != nil {
		log.Fatal(err)
	}

	createOpts := &bpf.BPFMapCreateOpts{
		BTFFD: uint32(btfFD),
	}
	innerArray, err := bpf.CreateMap(bpf.MapTypeArray, "inner_array", 4, 4, 1, createOpts)
	if err != nil {
		log.Fatal(err)
	}

	// Save an element in the "inner_array" map.
	key := uint32(0) // index 0
	keyUnsafe := unsafe.Pointer(&key)
	value := uint32(191711)
	valueUnsafe := unsafe.Pointer(&value)
	err = innerArray.Update(keyUnsafe, valueUnsafe)
	if err != nil {
		log.Fatal(err)
	}
}

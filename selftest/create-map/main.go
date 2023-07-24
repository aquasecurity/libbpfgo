package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// CreateMap uses `bpf_map_create()`, a 'low-level' API in libbpf
// As such, it does not have access to the higher level APIs in
// libbpf, which are denoted by starting with `bpf_map__*`.

// As such, you can use bpf_map_create() to populate arrays of maps
// in userspace, then iterate over those arrays on the bpf side, and
// use them as a normal map there as those operations only require
// a file descriptor.

// For example:
// https://elixir.bootlin.com/linux/latest/source/samples/bpf/fds_example.c
// https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/test_maps.c
// https://lore.kernel.org/bpf/CAO658oWagXsQDeFtRA2vZBzov7cwwVNTs5nHE9fMGrMOs6bbpQ@mail.gmail.com/

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	keySize := 4
	valueSize := 4
	maxEntries := 4

	// CreateMap()
	createdMapName1 := "created_1"
	opts1 := &bpf.BPFMapCreateOpts{}
	createdMap1, err := bpf.CreateMap(bpf.MapTypeHash, createdMapName1, keySize, valueSize, maxEntries, opts1)
	if err != nil {
		log.Fatal(err)
	}

	createdOuterMapName2 := "created_outer_2"
	opts2 := &bpf.BPFMapCreateOpts{
		InnerMapFD: uint32(createdMap1.FileDescriptor()),
	}
	createdOuterMap2, err := bpf.CreateMap(bpf.MapTypeHashOfMaps, createdOuterMapName2, keySize, valueSize, maxEntries, opts2)
	if err != nil {
		log.Fatal(err)
	}

	// Update()
	key1 := uint32(1)
	value1 := uint32(55)
	key1Pointer := unsafe.Pointer(&key1)
	value1Pointer := unsafe.Pointer(&value1)
	err = createdMap1.Update(key1Pointer, value1Pointer)
	if err != nil {
		log.Fatal(err)
	}

	// UpdateValueFlags()
	flags := bpf.MapFlag(0)
	err = createdMap1.UpdateValueFlags(key1Pointer, value1Pointer, flags)
	if err != nil {
		log.Fatal(err)
	}

	// GetValue()
	readValue, err := createdMap1.GetValue(key1Pointer)
	if err != nil {
		log.Fatal(err)
	}
	if endian().Uint32(readValue) != value1 {
		log.Fatal("map value not equal to expected value.")
	}

	// GetValueFlags()
	flags = bpf.MapFlag(0)
	readValueFlags, err := createdMap1.GetValueFlags(key1Pointer, flags)
	if err != nil {
		log.Fatal(err)
	}
	if endian().Uint32(readValueFlags) != value1 {
		log.Fatal("map value not equal to expected value.")
	}

	// GetValueReadInto() is unavailable for maps created with CreateMap(),
	// so this should fail.
	readValueReadInto := make([]byte, valueSize)
	err = createdMap1.GetValueReadInto(key1Pointer, &readValueReadInto)
	if err == nil {
		log.Fatal("this should have failed")
	}

	// UpdateBatch()
	// GetValueBatch()
	// GetValueAndDeleteBatch()
	// DeleteKeyBatch()

	// DeleteKey()
	err = createdMap1.DeleteKey(key1Pointer)
	if err != nil {
		log.Fatal(err)
	}
	readValue, err = createdMap1.GetValue(key1Pointer)
	if err == nil {
		log.Fatal("this should have failed")
	}

	// Name()
	if createdMap1.Name() != createdMapName1 {
		log.Fatal("map name not equal to expected name.")
	}
	if createdOuterMap2.Name() != createdOuterMapName2 {
		log.Fatal("map name not equal to expected name.")
	}

	// Type()
	if createdMap1.Type() != bpf.MapTypeHash {
		log.Fatal("map type not equal to expected type.")
	}
	if createdOuterMap2.Type() != bpf.MapTypeHashOfMaps {
		log.Fatal("map type not equal to expected type.")
	}

	// SetType() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.SetType(bpf.MapTypeArray)
	if err == nil {
		log.Fatal("this should have failed")
	}
	err = createdOuterMap2.SetType(bpf.MapTypeArray)
	if err == nil {
		log.Fatal(err)
	}

	// Pin()
	createdMap1PinPath := "/sys/fs/bpf/" + createdMapName1
	err = createdMap1.Pin(createdMap1PinPath)
	if err != nil {
		log.Fatal(err)
	}
	createOuterMap2PinPath := "/sys/fs/bpf/" + createdOuterMapName2
	err = createdOuterMap2.Pin(createOuterMap2PinPath)
	if err != nil {
		log.Fatal(err)
	}

	// PinPath() is unavailable for maps created with CreateMap(),
	// so this should fail.
	if createdMap1.PinPath() != "" {
		log.Fatal("map pin path not equal to expected pin path.")
	}

	// IsPinned() is unavailable for maps created with CreateMap(),
	// so this should return always false.
	if createdMap1.IsPinned() {
		log.Fatal("IsPinned() should return false.")
	}

	// UnPin()
	err = createdMap1.Unpin(createdMap1PinPath)
	if err != nil {
		log.Fatal(err)
	}
	err = createdOuterMap2.Unpin(createOuterMap2PinPath)
	if err != nil {
		log.Fatal(err)
	}

	// SetPinPath() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.SetPinPath(createdMap1PinPath)
	if err == nil {
		log.Fatal("this should have failed")
	}
	err = createdOuterMap2.SetPinPath(createOuterMap2PinPath)
	if err == nil {
		log.Fatal(err)
	}

	// SetInnerMap() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.SetInnerMap(createdMap1)
	if err == nil {
		log.Fatal("this should have failed")
	}

	// Resize() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.Resize(8)
	if err == nil {
		log.Fatal("this should have failed")
	}

	// GetMaxEntries()
	if createdMap1.GetMaxEntries() != uint32(maxEntries) {
		log.Fatal("map max entries not equal to expected max entries.")
	}
	if createdOuterMap2.GetMaxEntries() != uint32(maxEntries) {
		log.Fatal("map max entries not equal to expected max entries.")
	}

	// FileDescriptor()
	if createdMap1.FileDescriptor() <= 0 {
		log.Fatal("map file descriptor not greater than 0.")
	}
	if createdOuterMap2.FileDescriptor() <= 0 {
		log.Fatal("map file descriptor not greater than 0.")
	}

	// KeySize()
	if createdMap1.KeySize() != keySize {
		log.Fatal("map key size not equal to expected key size.")
	}
	if createdOuterMap2.KeySize() != keySize {
		log.Fatal("map key size not equal to expected key size.")
	}

	// ValueSize()
	if createdMap1.ValueSize() != valueSize {
		log.Fatal("map value size not equal to expected value size.")
	}
	if createdOuterMap2.ValueSize() != valueSize {
		log.Fatal("map value size not equal to expected value size.")
	}

	// SetValueSize() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.SetValueSize(8)
	if err == nil {
		log.Fatal("this should have failed")
	}

	// GetInfoByFD()
	info, err := createdMap1.GetInfoByFD()
	if err != nil {
		log.Fatal(err)
	}
	if info.Type != bpf.MapTypeHash {
		log.Fatal("map type not equal to expected type.")
	}
	if info.KeySize != uint32(keySize) {
		log.Fatal("map key size not equal to expected key size.")
	}
	if info.ValueSize != uint32(valueSize) {
		log.Fatal("map value size not equal to expected value size.")
	}
	if info.MaxEntries != uint32(maxEntries) {
		log.Fatal("map max entries not equal to expected max entries.")
	}
	if info.Name != createdMapName1 {
		log.Fatal("map name not equal to expected name.")
	}

	// Reload() is unavailable for maps created with CreateMap(),
	// so this should fail.
	err = createdMap1.Reload()
	if err == nil {
		log.Fatal("this should have failed")
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

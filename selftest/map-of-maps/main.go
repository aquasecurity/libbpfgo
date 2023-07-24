package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// This selftest deals with interactions involving hash maps and an array of maps.
// It utilizes the functions CreateMap(), SetInnerMap(), GetMapByID(), GetBTFFDByID()
// and Reload().

func main() {
	// In this test scenario, we are employing two outer BPF map types, specifically
	// BPF_MAP_TYPE_HASH_OF_MAPS and BPF_MAP_TYPE_ARRAY_OF_MAPS, referred to as
	// "outer_hash" and "outer_array" respectively, which are defined in the BPF
	// object file main.bpf.o. There is one other outer map created in userland,
	// referred to as "outer_hash_3", which is of type BPF_MAP_TYPE_HASH_OF_MAPS.
	//
	// In this case, the purpose of utilizing these outer BPF maps is to store
	// inner BPF map of type BPF_MAP_TYPE_HASH as entries.

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	//
	// Get BPF object outer maps by name.
	//

	// hash
	outerHashMap0, err := bpfModule.GetMap("outer_hash_0")
	if err != nil {
		log.Fatal(err)
	}

	// hash
	outerHashMap1, err := bpfModule.GetMap("outer_hash_1")
	if err != nil {
		log.Fatal(err)
	}

	// array
	outerArrayMap2, err := bpfModule.GetMap("outer_array_2")
	if err != nil {
		log.Fatal(err)
	}

	// When creating an outer map, an inner map instance is utilized to initialize
	// the metadata that the outer map holds about its inner maps.

	// hash metadata map (dummy)
	metadataInnerHashMap, err := bpf.CreateMap(bpf.MapTypeHash, "metadata_inner_hash", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := outerHashMap1.SetInnerMap(metadataInnerHashMap); err != nil {
		log.Fatal(err)
	}
	if err := outerArrayMap2.SetInnerMap(metadataInnerHashMap); err != nil {
		log.Fatal(err)
	}

	//
	// Load the BPF object and reload the outer maps not defined in the BPF object.
	//

	bpfModule.BPFLoadObject()

	// The reload call is needed to update the outer BPFMap internal fd value,
	// otherwise it will still be -1 as the internal fields of this object are
	// not updated by the BPFLoadObject call.

	// hash
	// NOTE: This map is already created in the BPF object file, so other way to
	// use it without concerns is to call bpfMod.GetMap("outer_hash_0") after the BPFLoadObject call.
	if err := outerHashMap0.Reload(); err != nil {
		log.Fatal(err)
	}

	// hash
	if err := outerHashMap1.Reload(); err != nil {
		log.Fatal(err)
	}

	// array
	if err := outerArrayMap2.Reload(); err != nil {
		log.Fatal(err)
	}

	//
	// Create outer map not defined in the BPF object.
	//

	opts := &bpf.BPFMapCreateOpts{
		InnerMapFD: uint32(metadataInnerHashMap.FileDescriptor()),
	}
	// Create a new outer map (not defined in BPF object file).
	outerHashMap3, err := bpf.CreateMap(bpf.MapTypeHashOfMaps, "outer_hash_3", 4, 4, 1, opts)
	if err != nil {
		log.Fatal(err)
	}

	//
	// Close metadata inner map.
	//

	// It is important to note that the inner map has a distinct lifetime from the outer map.
	// Once the outer map is successfully created, the initialization data from the inner map is no
	// longer required, and the inner map can be safely deleted independently of the outer map.
	if err := syscall.Close(metadataInnerHashMap.FileDescriptor()); err != nil {
		log.Fatal(err)
	}

	//
	// Create/get inner maps.
	//

	// hash map 0 (used for hash outer map 0)
	// NOTE: This map is already created in the BPF object file.
	innerHashMap0, err := bpfModule.GetMap("inner_hash_0")
	if err != nil {
		log.Fatal(err)
	}

	info, err := innerHashMap0.GetInfoByFD()
	if err != nil {
		log.Fatal(err)
	}
	btfFD, err := bpf.GetBTFFDByID(info.BTFID)
	if err != nil {
		log.Fatal(err)
	}
	opts = &bpf.BPFMapCreateOpts{
		BtfFD:                 uint32(btfFD),
		BtfKeyTypeID:          info.BTFKeyTypeID,
		BtfValueTypeID:        info.BTFValueTypeID,
		BtfVmlinuxValueTypeID: info.BTFVmlinuxValueTypeID,
		MapFlags:              info.MapFlags,
	}

	// hash map 1 (used for hash outer map 1)
	// this uses opts with info from innerHashMap0 to have the same BTF
	innerHashMap1, err := bpf.CreateMap(bpf.MapTypeHash, "inner_hash_1", 4, 4, 420, opts)
	if err != nil {
		log.Fatal(err)
	}

	// hash map 2 (used for array outer map)
	// this does not use opts, so it will have no BTF
	innerHashMap2, err := bpf.CreateMap(bpf.MapTypeHash, "inner_hash_2", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	// hash map 3 (used for hash outer map 2)
	// this does not use opts, so it will have no BTF
	innerHashMap3, err := bpf.CreateMap(bpf.MapTypeHash, "inner_hash_3", 4, 4, 420, nil)
	if err != nil {
		log.Fatal(err)
	}

	//
	// Insert into inner maps.
	//

	// hash map 0 (used for hash outer map 0)
	innerHashKey0 := uint32(0)
	innerHashValue0 := uint32(33)
	innerHashKeyPointer0 := unsafe.Pointer(&innerHashKey0)
	innerHashValuePointer0 := unsafe.Pointer(&innerHashValue0)
	if err := innerHashMap0.Update(innerHashKeyPointer0, innerHashValuePointer0); err != nil {
		log.Fatal(err)
	}

	// hash map 1 (used for hash outer map 1)
	innerHashKey1 := uint32(1)
	innerHashValue1 := uint32(42)
	innerHashKeyPointer1 := unsafe.Pointer(&innerHashKey1)
	innerHashValuePointer1 := unsafe.Pointer(&innerHashValue1)
	if err := innerHashMap1.Update(innerHashKeyPointer1, innerHashValuePointer1); err != nil {
		log.Fatal(err)
	}

	// hash map 2 (used for array outer map)
	innerHashKey2 := uint32(2)
	innerHashValue2 := uint32(51)
	innerHashKeyPointer2 := unsafe.Pointer(&innerHashKey2)
	innerHashValuePointer2 := unsafe.Pointer(&innerHashValue2)
	if err := innerHashMap2.Update(innerHashKeyPointer2, innerHashValuePointer2); err != nil {
		log.Fatal(err)
	}

	// hash map 3 (used for hash outer map 2)
	innerHashKey3 := uint32(3)
	innerHashValue3 := uint32(60)
	innerHashKeyPointer3 := unsafe.Pointer(&innerHashKey3)
	innerHashValuePointer3 := unsafe.Pointer(&innerHashValue3)
	if err := innerHashMap3.Update(innerHashKeyPointer3, innerHashValuePointer3); err != nil {
		log.Fatal(err)
	}

	//
	// Insert inner into outer maps.
	//

	// NOTE: The inner map ID is not the same as the inner map FD.
	//
	// The inner map FD is passed as the value to the outer map entry.
	// However what is really stored is the inner map ID. Remember that when doing lookups.

	// hash (innerHashMap0)
	// NOTE: This map is already inserted in the respective outer via BPF object file.
	outerHashKey0 := uint32(0)
	outerHashKeyPointer0 := unsafe.Pointer(&outerHashKey0)

	// hash (store innerHashMap1)
	outerHashKey1 := uint32(1)
	outerHashValue1 := uint32(innerHashMap1.FileDescriptor())
	outerHashKeyPointer1 := unsafe.Pointer(&outerHashKey1)
	outerHashValuePointer1 := unsafe.Pointer(&outerHashValue1)
	if err := outerHashMap1.Update(outerHashKeyPointer1, outerHashValuePointer1); err != nil {
		log.Fatal(err)
	}

	// array (store innerHashMap2)
	outerArrKey2 := uint32(0) // index 0
	outerArrValue2 := uint32(innerHashMap2.FileDescriptor())
	outerArrKeyPointer2 := unsafe.Pointer(&outerArrKey2)
	outerArrValuePointer2 := unsafe.Pointer(&outerArrValue2)
	if err := outerArrayMap2.Update(outerArrKeyPointer2, outerArrValuePointer2); err != nil {
		log.Fatal(err)
	}

	// hash (store innerHashMap3)
	outerHashKey3 := uint32(3)
	outerHashValue3 := uint32(innerHashMap3.FileDescriptor())
	outerHashKeyPointer3 := unsafe.Pointer(&outerHashKey3)
	outerHashValuePointer3 := unsafe.Pointer(&outerHashValue3)
	if err := outerHashMap3.Update(outerHashKeyPointer3, outerHashValuePointer3); err != nil {
		log.Fatal(err)
	}

	//
	// Read from outer and then inner maps, respectively.
	//

	// hash map 0 (read from outerHashMap0)
	outerHashVal0, err := outerHashMap0.GetValue(outerHashKeyPointer0)
	if err != nil {
		log.Fatal(err)
	}

	innerHashMapId0 := endian().Uint32(outerHashVal0)
	readHashInnerMap0, err := bpf.GetMapByID(innerHashMapId0)
	if err != nil {
		log.Fatal(err)
	}

	readHashInnerValue0, err := readHashInnerMap0.GetValue(innerHashKeyPointer0)
	if err != nil {
		log.Fatal(err)
	}

	if endian().Uint32(readHashInnerValue0) != innerHashValue0 {
		log.Fatal("Inner map value not equal to expected value.")
	}

	// hash map 1 (read from outerHashMap)
	outerHashVal1, err := outerHashMap1.GetValue(outerHashKeyPointer1)
	if err != nil {
		log.Fatal(err)
	}

	innerHashMapId1 := endian().Uint32(outerHashVal1)
	readHashInnerMap1, err := bpf.GetMapByID(innerHashMapId1)
	if err != nil {
		log.Fatal(err)
	}

	readHashInnerValue1, err := readHashInnerMap1.GetValue(innerHashKeyPointer1)
	if err != nil {
		log.Fatal(err)
	}

	if endian().Uint32(readHashInnerValue1) != innerHashValue1 {
		log.Fatal("Inner map value not equal to expected value.")
	}

	// hash map 2 (read from outerArrayMap1)
	outerArrVal, err := outerArrayMap2.GetValue(outerArrKeyPointer2)
	if err != nil {
		log.Fatal(err)
	}

	innerHashMapId2 := endian().Uint32(outerArrVal)
	readHashInnerMap2, err := bpf.GetMapByID(innerHashMapId2)
	if err != nil {
		log.Fatal(err)
	}

	readHashInnerValue2, err := readHashInnerMap2.GetValue(innerHashKeyPointer2)
	if err != nil {
		log.Fatal(err)
	}

	if endian().Uint32(readHashInnerValue2) != innerHashValue2 {
		log.Fatal("Inner map value not equal to expected value.")
	}

	// hash map 3 (read from outerHashMap2)
	outerHashVal2, err := outerHashMap3.GetValue(outerHashKeyPointer3)
	if err != nil {
		log.Fatal(err)
	}

	innerHashMapId3 := endian().Uint32(outerHashVal2)
	readHashInnerMap3, err := bpf.GetMapByID(innerHashMapId3)
	if err != nil {
		log.Fatal(err)
	}

	readHashInnerValue3, err := readHashInnerMap3.GetValue(innerHashKeyPointer3)
	if err != nil {
		log.Fatal(err)
	}

	if endian().Uint32(readHashInnerValue3) != innerHashValue3 {
		log.Fatal("Inner map value not equal to expected value.")
	}

	//
	// Delete from outer maps.
	//

	// hash 0
	if err := outerHashMap0.DeleteKey(outerHashKeyPointer0); err != nil {
		log.Fatal(err)
	}

	// hash 1
	if err := outerHashMap1.DeleteKey(outerHashKeyPointer1); err != nil {
		log.Fatal(err)
	}

	// array 2
	if err := outerArrayMap2.DeleteKey(outerArrKeyPointer2); err != nil {
		log.Fatal(err)
	}

	// hash 3
	if err := outerHashMap3.DeleteKey(outerHashKeyPointer3); err != nil {
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

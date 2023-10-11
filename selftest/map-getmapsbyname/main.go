package main

import "C"

import (
	"log"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	BPFMapNameToNotFind = "not_found"
	// The following properties are used to identify the map
	BPFHashMapNameToFind   = "test_hash_name"
	BPFMapNameToFind       = "test_name"
	BPFMapTypeToFind       = bpf.MapTypeArray
	BPFMapMaxEntriesToFind = 1
	BPFMapKeySizeToFind    = 4
	BPFMapValSizeToFind    = 4
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	notFoundMapsIDs, err := bpf.GetMapsIDsByName(BPFMapNameToNotFind)
	if len(notFoundMapsIDs) != 0 {
		log.Fatalf("the %s map should not be found, but it was found with ids: %v", BPFMapNameToNotFind, notFoundMapsIDs)
	}

	bpfHashMapsIDs, err := bpf.GetMapsIDsByName(BPFHashMapNameToFind)
	if len(bpfHashMapsIDs) == 0 {
		log.Fatalf("the %s map should be found", BPFHashMapNameToFind)
	}

	mapsIDs, err := bpf.GetMapsIDsByName(BPFMapNameToFind)
	if err != nil {
		log.Fatal(err)
	}
	if len(mapsIDs) == 0 {
		log.Fatalf("the %s map was not found", BPFMapNameToFind)
	}

	// try to identify the map by its properties
	similarMaps := []*bpf.BPFMapLow{}
	for _, id := range mapsIDs {
		bpfMap, err := bpf.GetMapByID(id)
		if err != nil {
			log.Fatalf("the %s map with %d id was not found: %v", BPFMapNameToFind, id, err)
		}

		if bpfMap.Type() == BPFMapTypeToFind &&
			bpfMap.MaxEntries() == BPFMapMaxEntriesToFind &&
			bpfMap.KeySize() == BPFMapKeySizeToFind &&
			bpfMap.ValueSize() == BPFMapValSizeToFind {
			// found a map with the same properties
			similarMaps = append(similarMaps, bpfMap)
		} else {
			if err := syscall.Close(bpfMap.FileDescriptor()); err != nil {
				log.Fatalf("failed to close the file descriptor of the %s map with %d id: %v", BPFMapNameToFind, id, err)
			}
		}
	}

	if len(similarMaps) == 0 {
		log.Fatalf("no %s maps with the same properties found", BPFMapNameToFind)
	}
	if len(similarMaps) > 1 {
		// This is a conundrum for the user, as they cannot decide which map to use
		// automatically. Perhaps they should change the name of the map to make it
		// unique.
		_ = 0
	}

	// use the first map of the similar ones
	bpfMap := similarMaps[0]

	key1 := uint32(0)
	value1 := uint32(55)
	if err := bpfMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value1)); err != nil {
		log.Fatal(err)
	}
}

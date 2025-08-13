package main

import "C"

import (
	"fmt"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
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
		common.Error(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	startId := uint32(0)
	notFoundMapsIDs, err := bpf.GetMapsIDsByName(BPFMapNameToNotFind, &startId)
	if len(notFoundMapsIDs) != 0 {
		common.Error(fmt.Errorf("the %s map should not be found, but it was found with ids: %v", BPFMapNameToNotFind, notFoundMapsIDs))
	}

	startId = 0
	bpfHashMapsIDs, err := bpf.GetMapsIDsByName(BPFHashMapNameToFind, &startId)
	if err != nil {
		common.Error(err)
	}
	if len(bpfHashMapsIDs) == 0 {
		common.Error(fmt.Errorf("the %s map should be found", BPFHashMapNameToFind))
	}

	startId = 0
	mapsIDs, err := bpf.GetMapsIDsByName(BPFMapNameToFind, &startId)
	if err != nil {
		common.Error(err)
	}
	if len(mapsIDs) == 0 {
		common.Error(fmt.Errorf("the %s map was not found", BPFMapNameToFind))
	}

	// try to identify the map by its properties
	similarMaps := []*bpf.BPFMapLow{}
	for _, id := range mapsIDs {
		bpfMap, err := bpf.GetMapByID(id)
		if err != nil {
			common.Error(fmt.Errorf("the %s map with %d id was not found: %v", BPFMapNameToFind, id, err))
		}

		if bpfMap.Type() == BPFMapTypeToFind &&
			bpfMap.MaxEntries() == BPFMapMaxEntriesToFind &&
			bpfMap.KeySize() == BPFMapKeySizeToFind &&
			bpfMap.ValueSize() == BPFMapValSizeToFind {
			// found a map with the same properties
			similarMaps = append(similarMaps, bpfMap)
		} else {
			if err := syscall.Close(bpfMap.FileDescriptor()); err != nil {
				common.Error(fmt.Errorf("failed to close the file descriptor of the %s map with %d id: %v", BPFMapNameToFind, id, err))
			}
		}
	}

	if len(similarMaps) == 0 {
		common.Error(fmt.Errorf("no %s maps with the same properties found", BPFMapNameToFind))
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
		common.Error(err)
	}
}

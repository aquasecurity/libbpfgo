package main

import "C"

import (
	"errors"
	"log"
	"syscall"
	"unsafe"

	"encoding/binary"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF module: %v", err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		log.Fatalf("Failed to get map: %v", err)
	}

	//
	// UpdateBatch
	//

	// Test batch update.
	keys := []uint32{1, 2, 3, 4}
	values := []uint32{2, 3, 4, 5}

	count, err := testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		log.Fatal(err)
	}
	if count != uint32(len(keys)) {
		log.Fatalf("Failed to batch update all elements: %d/%d", count, len(keys))
	}

	val, err := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err != nil {
		log.Fatal(err)
	}
	if endian().Uint32(val) != values[0] {
		log.Fatalf("testerMap.GetValue returned %v, expected %v", val, values[0])
	}

	// Test batch update.
	// Trying to update more entries than max_entries.
	keysGreater := []uint32{1, 2, 3, 4, 100} // 100 won't be added, since max_entries is 4.
	valuesGreater := []uint32{2, 3, 4, 5, 100}

	count, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keysGreater[0]),
		unsafe.Pointer(&valuesGreater[0]),
		uint32(len(keysGreater)),
	)
	if err != nil {
		log.Fatal(err)
	}
	if count == uint32(len(keysGreater)) {
		log.Fatalf("count %d should be less than len(keysGreater) %d", count, len(keysGreater))
	}

	//
	// GetValueBatch
	//

	// Test batch lookup in steps.
	batchKeys := make([]uint32, 3)
	startKeyPtr := unsafe.Pointer(nil)
	nextKey := uint64(0)
	stepSize := len(batchKeys)
	for i := 0; i < 2; i++ {
		vals, _, err := testerMap.GetValueBatch(
			unsafe.Pointer(&batchKeys[0]),
			startKeyPtr,
			unsafe.Pointer(&nextKey),
			uint32(stepSize),
		)
		if err != nil {
			log.Fatalf("Failed to batch lookup: %v", err)
		}

		startKeyPtr = unsafe.Pointer(&nextKey)

		for i, val := range vals {
			actual := endian().Uint32(val)
			expected := batchKeys[i] + 1
			if actual != expected {
				log.Fatalf("testerMap.GetValueBatch returned %v, expected %v", actual, expected)
			}
		}
	}

	// Test batch lookup an unavailable key between available keys.
	notAllAvailableKeys := []uint32{10, 1, 2, 3, 4} // 10 is not in the map.
	expectedCount := uint32(len(notAllAvailableKeys) - 1)
	startKeyPtr = unsafe.Pointer(nil)
	nextKey = uint64(0)
	_, count, err = testerMap.GetValueBatch(
		unsafe.Pointer(&notAllAvailableKeys[0]),
		startKeyPtr,
		unsafe.Pointer(&nextKey),
		uint32(len(notAllAvailableKeys)),
	)
	if err != nil {
		log.Fatal(err)
	}
	if count != expectedCount {
		log.Fatalf("Failed to partial batch lookup elements: %d/%d", count, len(keys))
	}

	// Test batch lookup passing a count that is greater than the number of
	// available elements.
	greaterCount := len(batchKeys) + 10
	startKeyPtr = unsafe.Pointer(nil)
	nextKey = uint64(0)
	_, count, err = testerMap.GetValueBatch(
		unsafe.Pointer(&batchKeys[0]),
		startKeyPtr,
		unsafe.Pointer(&nextKey),
		uint32(greaterCount),
	)
	if err != nil {
		log.Fatal(err)
	}

	//
	// GetValueAndDeleteBatch
	//

	// Test batch lookup and delete in steps.
	totalKeysToDelete := uint32(3)
	stepSize = 1
	step := 0
	for totalKeysToDelete > 0 && step < 10 {
		if totalKeysToDelete < uint32(stepSize) {
			stepSize = int(totalKeysToDelete)
		}
		deleteKeys := make([]uint32, stepSize)
		startKeyPtr = unsafe.Pointer(nil)
		nextKey = uint64(0)
		vals, count, err := testerMap.GetValueAndDeleteBatch(
			unsafe.Pointer(&deleteKeys[0]),
			startKeyPtr,
			unsafe.Pointer(&nextKey),
			uint32(stepSize),
		)
		if err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				// Reference:
				// https://elixir.bootlin.com/linux/v6.4.13/source/tools/testing/selftests/bpf/map_tests/htab_map_batch_ops.c#L158
				log.Printf("totalKeysToDelete: %d, step: %d, stepSize: %d", totalKeysToDelete, step, stepSize)
				if uint32(stepSize) < totalKeysToDelete {
					stepSize++
				}

				step++
				continue
			}
			log.Fatal(err)
		}
		log.Printf("testerMap.GetValueAndDeleteBatch deleted element(s): %d", count)
		totalKeysToDelete -= count

		for i, val := range vals {
			actual := endian().Uint32(val)
			expected := deleteKeys[i] + 1
			if actual != expected {
				log.Fatalf("testerMap.GetValueAndDeleteBatch returned %v, expected %v", actual, expected)
			}
		}
	}
	if totalKeysToDelete != 0 {
		// Don't fail, since this should not always work.
		log.Printf("Due to ENOSPC, not all keys were deleted, remaining: %d", totalKeysToDelete)
	}

	//
	// DeleteKeyBatch
	//

	// Re-add deleted entries.
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		log.Fatal(err)
	}

	// map is full again.

	// Test batch delete.
	// Trying to delete more keys than we have.
	count, err = testerMap.DeleteKeyBatch(
		unsafe.Pointer(&keys[0]),
		uint32(len(keys)+10),
	)
	if err != nil {
		log.Fatal(err)
	}
	if count != uint32(len(keys)) {
		log.Fatalf("testerMap.DeleteKeyBatch failed: count=%d", count)
	}

	// Ensure value is no longer there.
	v, _ := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if len(v) != 0 {
		log.Fatalf("testerMap.GetValue was expected to fail, but succeeded")
	}

	// map is empty again.

	// Re-add deleted entries.
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Test batch delete.
	// Trying to delete fewer or equal keys than we have.
	fewer := 3
	count, err = testerMap.DeleteKeyBatch(
		unsafe.Pointer(&keys[0]),
		uint32(fewer),
	)
	if err != nil {
		log.Fatal(err)
	}
	if count != uint32(fewer) {
		log.Fatalf("testerMap.DeleteKeyBatch failed: count=%d", count)
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

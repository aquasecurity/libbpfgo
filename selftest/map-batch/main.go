package main

import "C"

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(fmt.Errorf("failed to load BPF module: %v", err))
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		common.Error(fmt.Errorf("failed to get map: %v", err))
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
		common.Error(err)
	}
	if count != uint32(len(keys)) {
		common.Error(fmt.Errorf("failed to batch update all elements: %d/%d", count, len(keys)))
	}

	val, err := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err != nil {
		common.Error(err)
	}
	if common.ByteOrder().Uint32(val) != values[0] {
		common.Error(fmt.Errorf("testerMap.GetValue returned %v, expected %v", val, values[0]))
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
		common.Error(err)
	}
	if count == uint32(len(keysGreater)) {
		common.Error(fmt.Errorf("count %d should be less than len(keysGreater) %d", count, len(keysGreater)))
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
			common.Error(fmt.Errorf("failed to batch lookup: %v", err))
		}

		startKeyPtr = unsafe.Pointer(&nextKey)

		for i, val := range vals {
			actual := common.ByteOrder().Uint32(val)
			expected := batchKeys[i] + 1
			if actual != expected {
				common.Error(fmt.Errorf("testerMap.GetValueBatch returned %v, expected %v", actual, expected))
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
		common.Error(err)
	}
	if count != expectedCount {
		common.Error(fmt.Errorf("failed to partial batch lookup elements: %d/%d", count, expectedCount))
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
		common.Error(err)
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
			common.Error(err)
		}
		log.Printf("testerMap.GetValueAndDeleteBatch deleted element(s): %d", count)
		totalKeysToDelete -= count

		for i, val := range vals {
			actual := common.ByteOrder().Uint32(val)
			expected := deleteKeys[i] + 1
			if actual != expected {
				common.Error(fmt.Errorf("testerMap.GetValueAndDeleteBatch returned %v, expected %v", actual, expected))
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
		common.Error(err)
	}

	// map is full again.

	// Test batch delete.
	// Trying to delete more keys than we have.
	count, err = testerMap.DeleteKeyBatch(
		unsafe.Pointer(&keys[0]),
		uint32(len(keys)+10),
	)
	if err != nil {
		common.Error(err)
	}
	if count != uint32(len(keys)) {
		common.Error(fmt.Errorf("testerMap.DeleteKeyBatch failed: count=%d", count))
	}

	// Ensure value is no longer there.
	v, _ := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if len(v) != 0 {
		common.Error(errors.New("testerMap.GetValue was expected to fail, but succeeded"))
	}

	// map is empty again.

	// Re-add deleted entries.
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		common.Error(err)
	}

	// Test batch delete.
	// Trying to delete fewer or equal keys than we have.
	fewer := 3
	count, err = testerMap.DeleteKeyBatch(
		unsafe.Pointer(&keys[0]),
		uint32(fewer),
	)
	if err != nil {
		common.Error(err)
	}
	if count != uint32(fewer) {
		common.Error(fmt.Errorf("testerMap.DeleteKeyBatch failed: count=%d", count))
	}

	// map contains only 1 key-value pair.

	// Re-add deleted entries.
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		common.Error(err)
	}

	//
	// GetNextKey
	//

	// Populate the map again.
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		common.Error(err)
	}

	// Test GetNextKey.
	key := uint32(0)
	keyPtr := unsafe.Pointer(&key)
	keyCnt := 0
	for {
		err := testerMap.GetNextKey(keyPtr, keyPtr)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) {
				common.Error(fmt.Errorf("testerMap.GetNextKey failed: err=%v", err))
			}
			break
		}
		keyCnt++
	}
	if keyCnt != len(keys) {
		common.Error(fmt.Errorf("testerMap.GetNextKey failed: count=%d", keyCnt))
	}

	//
	// GetValueAndDeleteKey
	//

	// Test GetValueAndDeleteKey.
	for i, key := range keys {
		val, err := testerMap.GetValueAndDeleteKey(unsafe.Pointer(&key))
		if err != nil {
			common.Error(fmt.Errorf("testerMap.GetValueAndDelete failed: err=%v", err))
		}

		if common.ByteOrder().Uint32(val) != values[i] {
			common.Error(fmt.Errorf("testerMap.GetValueAndDelete failed: val=%d", common.ByteOrder().Uint32(val)))
		}
	}

	// Check if all keys are deleted.
	key = 0
	err = testerMap.GetNextKey(keyPtr, keyPtr)
	if !errors.Is(err, syscall.ENOENT) {
		common.Error(fmt.Errorf("testerMap.GetValueAndDeleteKey failed: err=%v", err))
	}
}

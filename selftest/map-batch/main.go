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

	log.Printf("[TEST] Starting UpdateBatch tests")

	// Test batch update.
	log.Printf("[TEST] UpdateBatch: Testing basic batch update")
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
	log.Printf("[TEST] UpdateBatch: Testing overflow (more entries than max_entries)")
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

	log.Printf("[TEST] Starting GetValueBatch tests")

	// Test batch lookup in steps.
	log.Printf("[TEST] GetValueBatch: Testing iterative batch lookup")
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
			// ENOENT means we've finished iterating through all elements
			if errors.Is(err, syscall.ENOENT) {
				break
			}
			common.Error(fmt.Errorf("failed to batch lookup: %v", err))
		}

		startKeyPtr = unsafe.Pointer(&nextKey)

		for i, val := range vals {
			actual := common.ByteOrder().Uint32(val)
			expected := batchKeys[i] + 1
			if actual != expected {
				common.Error(fmt.Errorf("GetValueBatch returned %v, expected %v", actual, expected))
			}
		}
	}

	// Test batch lookup with larger batch size than map content
	// This should return all elements in the map
	log.Printf("[TEST] GetValueBatch: Testing with large batch size")
	largeBatchKeys := make([]uint32, 10) // Larger than map size (4)
	startKeyPtr = unsafe.Pointer(nil)
	nextKey = uint64(0)

	var batchCount uint32
	_, batchCount, err = testerMap.GetValueBatch(
		unsafe.Pointer(&largeBatchKeys[0]),
		startKeyPtr,
		unsafe.Pointer(&nextKey),
		uint32(len(largeBatchKeys)),
	)

	if err != nil {
		common.Error(err)
	}
	// Should get exactly 4 elements (the size of our map)
	if batchCount != 4 {
		common.Error(fmt.Errorf("expected to get 4 elements, got %d", batchCount))
	}

	// Test batch lookup starting from a non-existent key
	// This tests iteration behavior when startKey doesn't exist in the map
	log.Printf("[TEST] GetValueBatch: Testing iteration starting from non-existent key")
	nonExistentKey := uint32(100) // This key is not in the map
	iterationKeys := make([]uint32, 4)
	startKeyPtr = unsafe.Pointer(&nonExistentKey)
	nextKey = uint64(0)

	_, iterationCount, err := testerMap.GetValueBatch(
		unsafe.Pointer(&iterationKeys[0]),
		startKeyPtr,
		unsafe.Pointer(&nextKey),
		uint32(len(iterationKeys)),
	)

	if err != nil && !errors.Is(err, syscall.ENOENT) {
		common.Error(fmt.Errorf("GetValueBatch with non-existent start key failed: %v", err))
	}
	// Should either find some keys (if iteration continues past non-existent key)
	// or return ENOENT (if no more keys), both are valid behaviors
	log.Printf("[TEST] GetValueBatch: Non-existent key iteration returned %d elements", iterationCount)

	// Test batch lookup with count greater than available elements.
	log.Printf("[TEST] GetValueBatch: Testing with count greater than available elements")
	greaterCount := len(batchKeys) + 10
	startKeyPtr = unsafe.Pointer(nil)
	nextKey = uint64(0)

	_, _, err = testerMap.GetValueBatch(
		unsafe.Pointer(&batchKeys[0]),
		startKeyPtr,
		unsafe.Pointer(&nextKey),
		uint32(greaterCount),
	)

	if err != nil {
		// ENOENT is expected if iteration is already complete
		if !errors.Is(err, syscall.ENOENT) {
			common.Error(err)
		}
	}

	//
	// GetValueAndDeleteBatch
	//

	log.Printf("[TEST] Starting GetValueAndDeleteBatch tests")

	// Test batch lookup and delete in steps.
	// We should have 4 keys in the map at this point: [1, 2, 3, 4]
	totalKeysToDelete := uint32(4)
	stepSize = 1
	log.Printf("[TEST] GetValueAndDeleteBatch: Attempting to delete %d keys starting with batch size %d", totalKeysToDelete, stepSize)
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
				// ENOSPC occurs when hash bucket contains more elements than batch size
				// Reference:
				// https://elixir.bootlin.com/linux/v6.4.13/source/tools/testing/selftests/bpf/map_tests/htab_map_batch_ops.c#L158
				if uint32(stepSize) < totalKeysToDelete {
					log.Printf("[ENOSPC] GetValueAndDeleteBatch: Hash bucket collision detected.\n"+
						"  Remaining keys: %d, retry step: %d, current batch size: %d, increasing to: %d",
						totalKeysToDelete, step, stepSize, stepSize+1)
					stepSize++
				}

				step++
				continue
			}
			common.Error(err)
		}
		log.Printf("GetValueAndDeleteBatch deleted element(s): %d", count)
		totalKeysToDelete -= count

		for i, val := range vals {
			actual := common.ByteOrder().Uint32(val)
			expected := deleteKeys[i] + 1
			if actual != expected {
				common.Error(fmt.Errorf("GetValueAndDeleteBatch returned %v, expected %v", actual, expected))
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

	log.Printf("[TEST] Starting DeleteKeyBatch tests")

	// Re-add deleted entries.
	log.Printf("[TEST] DeleteKeyBatch: Re-adding entries for testing")
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
	log.Printf("[TEST] DeleteKeyBatch: Testing delete more keys than available")
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
	log.Printf("[TEST] DeleteKeyBatch: Testing delete fewer keys than available")
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
	log.Printf("[TEST] DeleteKeyBatch: Re-adding entries for GetNextKey test")
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

	log.Printf("[TEST] Starting GetNextKey tests")

	// Populate the map again.
	log.Printf("[TEST] GetNextKey: Populating map for iteration test")
	_, err = testerMap.UpdateBatch(
		unsafe.Pointer(&keys[0]),
		unsafe.Pointer(&values[0]),
		uint32(len(keys)),
	)
	if err != nil {
		common.Error(err)
	}

	// Test GetNextKey.
	log.Printf("[TEST] GetNextKey: Testing key iteration")
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

	log.Printf("[TEST] Starting GetValueAndDeleteKey tests")

	// Test GetValueAndDeleteKey.
	log.Printf("[TEST] GetValueAndDeleteKey: Testing individual key deletion")
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
	log.Printf("[TEST] GetValueAndDeleteKey: Verifying all keys are deleted")
	key = 0
	err = testerMap.GetNextKey(keyPtr, keyPtr)
	if !errors.Is(err, syscall.ENOENT) {
		common.Error(fmt.Errorf("testerMap.GetValueAndDeleteKey failed: err=%v", err))
	}

	log.Printf("[TEST] All map-batch tests completed successfully!")
}

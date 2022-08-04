package main

import "C"

import (
	"os"
	"unsafe"

	"encoding/binary"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	keys := []uint32{1, 2, 3, 4, 5, 6, 8}
	values := []uint32{2, 3, 4, 5, 6, 7, 9}

	// Test batch update.
	if err := testerMap.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), uint32(len(keys))); err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.UpdateBatch failed: %v", err)
		os.Exit(-1)
	}
	val, err := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.GetValue failed: %v", err)
		os.Exit(-1)
	}
	if binary.LittleEndian.Uint32(val) != values[0] {
		fmt.Fprintf(os.Stderr, "testerMap.GetValue returned %v, expected %v", val, values[0])
		os.Exit(-1)
	}

	// Test batch lookup in steps.
	batchKeys := make([]uint32, 3)
	nextKey := uint32(0)
	prevKey := unsafe.Pointer(nil)
	step := len(batchKeys)
	for i := 0; i < 2; i++ {
		if i > 0 {
			// We're on step 2, so test the batch lookup by specifying the
			// key to start from.
			prevKey = unsafe.Pointer(&nextKey)
		}
		vals, err := testerMap.GetValueBatch(unsafe.Pointer(&batchKeys[0]), prevKey, unsafe.Pointer(&nextKey), uint32(step))
		if err != nil {
			fmt.Fprintf(os.Stderr, "step %d testerMap.LookupBatch failed: %v", i, err)
			os.Exit(-1)
		}
		for i, val := range vals {
			actual := binary.LittleEndian.Uint32(val)
			expected := batchKeys[i] + 1
			if actual != expected {
				fmt.Fprintf(os.Stderr, "testerMap.LookupBatch returned %v, expected %v", actual, expected)
				os.Exit(-1)
			}
		}
	}

	// Test batch get value with more elements than we have.
	_, err = testerMap.GetValueBatch(unsafe.Pointer(&batchKeys[0]), prevKey, unsafe.Pointer(&nextKey), uint32(len(batchKeys))+100)
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.GetValueBatch failed: %v", err)
		os.Exit(-1)
	}

	// Test batch lookup and delete.
	deleteKeys := make([]uint32, 2)
	nextKey = uint32(0)
	requestedCount := len(deleteKeys)

	vals, err := testerMap.GetValueAndDeleteBatch(unsafe.Pointer(&deleteKeys[0]), nil, unsafe.Pointer(&nextKey), uint32(requestedCount))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.LookupBatch failed: %v", err)
		os.Exit(-1)
	}
	processedCount := len(vals)
	if requestedCount != processedCount {
		fmt.Fprintf(os.Stderr, "testerMap.LookupBatch failed: %d!=%d", requestedCount, processedCount)
		os.Exit(-1)
	}
	for i, val := range vals {
		actual := binary.LittleEndian.Uint32(val)
		expected := deleteKeys[i] + 1
		if actual != expected {
			fmt.Fprintf(os.Stderr, "testerMap.LookupBatch returned %v, expected %v", actual, expected)
			os.Exit(-1)
		}
	}

	if err := testerMap.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), uint32(len(keys))); err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.UpdateBatch failed: %v", err)
		os.Exit(-1)
	}

	// Test batch delete.
	// Trying to delete more keys than we have.
	err = testerMap.DeleteKeyBatch(unsafe.Pointer(&keys[0]), uint32(len(keys)+100))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.DeleteKeyBatch was expected to not fail")
		os.Exit(-1)
	}

	// Ensure value is no longer there.
	_, err = testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err == nil {
		fmt.Fprintf(os.Stderr, "testerMap.GetValue was expected to fail, but succeeded")
		os.Exit(-1)
	}

	// Re-add deleted entries.
	if err := testerMap.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), uint32(len(keys))); err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.UpdateBatch failed: %v", err)
		os.Exit(-1)
	}

	// Test batch delete.
	// Trying to delete fewer or equal keys than we have.
	err = testerMap.DeleteKeyBatch(unsafe.Pointer(&keys[0]), uint32(len(keys)-1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.DeleteKeyBatch was expected to not fail")
		os.Exit(-1)
	}

	// Test batch lookup and delete when requesting more elements than are in the map.
	deleteKeys = make([]uint32, 3)
	nextKey = uint32(0)
	requestedCount = 5

	vals, err = testerMap.GetValueAndDeleteBatch(unsafe.Pointer(&deleteKeys[0]), nil, unsafe.Pointer(&nextKey), uint32(requestedCount))
	if err != nil {
		fmt.Fprintf(os.Stderr, "testerMap.LookupBatch failed: %v", err)
		os.Exit(-1)
	}
	processedCount = len(vals)

	// We removed all but one element in the test case before.
	if processedCount != 1 {
		fmt.Fprintf(os.Stderr, "testerMap.LookupBatch failed: processedCount=%d", processedCount)
		os.Exit(-1)
	}
}

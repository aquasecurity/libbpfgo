package libbpfgo

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"testing"
	"unsafe"
)

func Test_LoadAndAttach(t *testing.T) {
	// load non exisiting file, should fail
	module, err := NewModuleFromFile("foo.bpf.o")
	if err == nil {
		t.Errorf("NewModuleFromFile returned nil error on non-existing file")
	}

	module, err = NewModuleFromFile("selftest/build/libbpfgo_test.bpf.o")
	if err != nil {
		t.Fatalf("NewModuleFromFile failed: %v", err)
	}
	defer module.Close()

	// load non exisiting program, should fail
	if err = module.BPFLoadObject(); err != nil {
		t.Fatalf("BPFLoadObject failed: %v", err)
	}

	// get non exisiting program, should fail
	_, err = module.GetProgram("foo")
	if err == nil {
		t.Errorf("GetProgram returned nil error on non-existing program")
	}

	attachTests := []struct {
		prog      string
		attachArg string
		attachFn  func(*BPFProg, string) (*BPFLink, error)
	}{
		{
			prog:      "tracepoint__sys_enter_dup",
			attachArg: "syscalls:sys_enter_dup",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				tpEvent := strings.Split(name, ":")
				if len(tpEvent) != 2 {
					return nil, fmt.Errorf("tracepoint must be in 'category:name' format")
				}
				return prog.AttachTracepoint(tpEvent[0], tpEvent[1])
			},
		},
		{
			prog:      "raw_tracepoint__sched_switch",
			attachArg: "sched_switch",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				return prog.AttachRawTracepoint(name)
			},
		},
		{
			prog:      "kprobe__get_task_pid",
			attachArg: "get_task_pid",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				return prog.AttachKprobe(name)
			},
		},
		{
			prog:      "kretprobe__get_task_pid",
			attachArg: "get_task_pid",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				return prog.AttachKretprobe(name)
			},
		},
		{
			prog:      "kprobe__get_task_pid",
			attachArg: "get_task_pid",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				return prog.AttachKprobeLegacy(name)
			},
		},
		{
			prog:      "kretprobe__get_task_pid",
			attachArg: "get_task_pid",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				return prog.AttachKretprobeLegacy(name)
			},
		},
		{
			prog: "socket_connect",
			attachFn: func(prog *BPFProg, name string) (*BPFLink, error) {
				if name != "" {
					// to make the check for attaching with "foo" happy
					return nil, fmt.Errorf("name not empty")
				}
				return prog.AttachLSM()
			},
		},
	}

	for i, test := range attachTests {
		prog, err := module.GetProgram(test.prog)
		if err != nil {
			t.Errorf("test %v: GetProgram(%q) failed: %v", i, test.prog, err)
			continue
		}

		// make sure it handles errors ok
		if _, err = test.attachFn(prog, "foo"); err == nil {
			t.Errorf("test %v: failure to attach expected", i)
		}

		if _, err = test.attachFn(prog, test.attachArg); err != nil {
			t.Errorf("test %v: attach failed: %v", i, err)
		}
	}
}

func Test_MapBatchOperations(t *testing.T) {
	module, err := NewModuleFromFile("selftest/build/libbpfgo_test.bpf.o")
	if err != nil {
		t.Fatalf("NewModuleFromFile failed: %v", err)
	}
	defer module.Close()
	module.BPFLoadObject()

	testerMap, err := module.GetMap("tester")
	if err != nil {
		t.Fatalf("module.GetMap failed: %v", err)
	}

	keys := []uint32{1, 2, 3, 4, 5, 6, 8}
	values := []uint32{2, 3, 4, 5, 6, 7, 9}

	// Test batch update.
	if err := testerMap.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), uint32(len(keys))); err != nil {
		t.Fatalf("testerMap.UpdateBatch failed: %v", err)
	}
	val, err := testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err != nil {
		t.Fatalf("testerMap.GetValue failed: %v", err)
	}
	if binary.LittleEndian.Uint32(val) != values[0] {
		t.Fatalf("testerMap.GetValue returned %v, expected %v", val, values[0])
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
			log.Printf("prevKey: %v", prevKey)
		}
		vals, err := testerMap.GetValueBatch(unsafe.Pointer(&batchKeys[0]), prevKey, unsafe.Pointer(&nextKey), uint32(step))
		if err != nil {
			t.Fatalf("step %d testerMap.LookupBatch failed: %v", i, err)
		}
		for i, val := range vals {
			actual := binary.LittleEndian.Uint32(val)
			expected := batchKeys[i] + 1
			if actual != expected {
				t.Fatalf("testerMap.LookupBatch returned %v, expected %v", actual, expected)
			}
		}
	}

	// Test batch lookup and delete.
	deleteKeys := make([]uint32, 3)
	nextKey = uint32(0)
	vals, err := testerMap.GetValueAndDeleteBatch(unsafe.Pointer(&deleteKeys[0]), nil, unsafe.Pointer(&nextKey), uint32(len(deleteKeys)))
	if err != nil {
		t.Fatalf("testerMap.LookupBatch failed: %v", err)
	}
	for i, val := range vals {
		actual := binary.LittleEndian.Uint32(val)
		expected := deleteKeys[i] + 1
		if actual != expected {
			t.Fatalf("testerMap.LookupBatch returned %v, expected %v", actual, expected)
		}
	}

}
func Test_MapBatchDeleteOperations(t *testing.T) {
	module, err := NewModuleFromFile("selftest/build/libbpfgo_test.bpf.o")
	if err != nil {
		t.Fatalf("NewModuleFromFile failed: %v", err)
	}
	defer module.Close()
	module.BPFLoadObject()

	testerMap, err := module.GetMap("tester")
	if err != nil {
		t.Fatalf("module.GetMap failed: %v", err)
	}

	keys := []uint32{1, 2, 3, 4, 5, 6, 8}
	values := []uint32{2, 3, 4, 5, 6, 7, 9}

	// Test batch update.
	if err := testerMap.UpdateBatch(unsafe.Pointer(&keys[0]), unsafe.Pointer(&values[0]), uint32(len(keys))); err != nil {
		t.Fatalf("testerMap.UpdateBatch failed: %v", err)
	}
	// Test batch delete.
	testerMap.DeleteKeyBatch(unsafe.Pointer(&keys[0]), uint32(len(keys)))

	// Ensure value is no longer there.
	_, err = testerMap.GetValue(unsafe.Pointer(&keys[0]))
	if err == nil {
		t.Fatalf("testerMap.GetValue was expected to fail, but succeeded")
	}
}

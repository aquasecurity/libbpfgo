package libbpfgo

import (
	"fmt"
	"strings"
	"testing"
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

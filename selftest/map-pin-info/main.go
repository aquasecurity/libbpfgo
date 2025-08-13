package main

import "C"

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func getSupposedPinPath(m *bpf.BPFMap) string {
	return "/sys/fs/bpf/" + m.GetName()
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	pinnedMap, err := bpfModule.GetMap("pinned_map")
	if err != nil {
		common.Error(err)
	}
	var supposedPinPath = getSupposedPinPath(pinnedMap)
	var actualPinPath string

	defer pinnedMap.Unpin(supposedPinPath)

	if !pinnedMap.IsPinned() {
		common.Error(fmt.Errorf("IsPinned() returned 'false' when map %s should be pinned", pinnedMap.Name()))
	}

	actualPinPath = pinnedMap.PinPath()
	if actualPinPath != supposedPinPath {
		common.Error(fmt.Errorf("PinPath() returned %s when should be %s",
			actualPinPath, supposedPinPath))
	}

	notPinnedMap, err := bpfModule.GetMap("not_pinned_map")
	if err != nil {
		common.Error(err)
	}

	if notPinnedMap.IsPinned() {
		common.Error(fmt.Errorf("IsPinned() returned 'true' when map %s should not be pinned", notPinnedMap.Name()))
	}

	supposedPinPath = getSupposedPinPath(notPinnedMap)

	notPinnedMap.Pin(supposedPinPath)
	defer notPinnedMap.Unpin(supposedPinPath)

	actualPinPath = notPinnedMap.PinPath()
	if actualPinPath != supposedPinPath {
		common.Error(fmt.Errorf("PinPath() returned %s when should be %s",
			actualPinPath, supposedPinPath))
	}
}

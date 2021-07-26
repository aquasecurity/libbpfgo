package main

import "C"

import (
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

func getSupposedPinPath(m *bpf.BPFMap) string {
	return "/sys/fs/bpf/" + m.GetName()
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	pinnedMap, err := bpfModule.GetMap("pinned_map")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	var supposedPinPath = getSupposedPinPath(pinnedMap)
	var actualPinPath string

	defer pinnedMap.Unpin(supposedPinPath)

	if !pinnedMap.IsPinned() {
		fmt.Fprintf(os.Stderr,
			"IsPinned() returned 'false' when map %s should be pinned\n",
			pinnedMap.GetName())
		os.Exit(-1)
	}

	actualPinPath = pinnedMap.GetPinPath()
	if actualPinPath != supposedPinPath {
		fmt.Fprintf(os.Stderr,
			"GetPinPath() returned %s when should be %s\n",
			actualPinPath, supposedPinPath)
		os.Exit(-1)
	}

	notPinnedMap, err := bpfModule.GetMap("not_pinned_map")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if notPinnedMap.IsPinned() {
		fmt.Fprintf(os.Stderr,
			"IsPinned() returned 'true' when map %s should not be pinned\n",
			pinnedMap.GetName())
		os.Exit(-1)
	}

	supposedPinPath = getSupposedPinPath(notPinnedMap)

	notPinnedMap.Pin(supposedPinPath)
	defer notPinnedMap.Unpin(supposedPinPath)

	actualPinPath = notPinnedMap.GetPinPath()
	if actualPinPath != supposedPinPath {
		fmt.Fprintf(os.Stderr,
			"GetPinPath() returned %s when should be %s\n",
			actualPinPath, supposedPinPath)
		os.Exit(-1)
	}
}

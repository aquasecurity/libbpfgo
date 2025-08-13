package common

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// ResizeMap resizes a BPF map to the specified size.
func ResizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.SetMaxEntries(size); err != nil {
		return err
	}

	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

// KSymArch returns the kernel symbol architecture.
func KSymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}

// ByteOrder returns the byte order of the system.
func ByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

// GetCgroupV2RootDir returns the root directory of the cgroupv2 filesystem.
func GetCgroupV2RootDir() (string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("read /proc/mounts failed: %+v", err)
	}

	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		return "", errors.New("cgroupv2 is not mounted")
	}

	return items[1], nil
}

// SymbolToOffset attempts to resolve a 'symbol' name in the binary found at
// 'path' to an offset. The offset can be used for attaching a u(ret)probe
func SymbolToOffset(path, symbol string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("could not open elf file to resolve symbol offset: %w", err)
	}
	defer f.Close()

	regularSymbols, regularSymbolsErr := f.Symbols()
	dynamicSymbols, dynamicSymbolsErr := f.DynamicSymbols()

	// Only if we failed getting both regular and dynamic symbols - then we abort.
	if regularSymbolsErr != nil && dynamicSymbolsErr != nil {
		return 0, fmt.Errorf("could not open regular or dynamic symbol sections to resolve symbol offset: %w %s", regularSymbolsErr, dynamicSymbolsErr)
	}

	// Concatenating into a single list.
	// The list can have duplications, but we will find the first occurrence which is sufficient.
	syms := append(regularSymbols, dynamicSymbols...)

	sectionsToSearchForSymbol := []*elf.Section{}

	for i := range f.Sections {
		if f.Sections[i].Flags == elf.SHF_ALLOC+elf.SHF_EXECINSTR {
			sectionsToSearchForSymbol = append(sectionsToSearchForSymbol, f.Sections[i])
		}
	}

	var executableSection *elf.Section

	for j := range syms {
		if syms[j].Name == symbol {
			// Find what section the symbol is in by checking the executable section's
			// addr space.
			for m := range sectionsToSearchForSymbol {
				if syms[j].Value > sectionsToSearchForSymbol[m].Addr &&
					syms[j].Value < sectionsToSearchForSymbol[m].Addr+sectionsToSearchForSymbol[m].Size {
					executableSection = sectionsToSearchForSymbol[m]
				}
			}

			if executableSection == nil {
				return 0, errors.New("could not find symbol in executable sections of binary")
			}

			return syms[j].Value - executableSection.Addr + executableSection.Offset, nil
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbol, path)
}

// Ordered constraint for comparable types
type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64 |
		~string
}

// Min returns the minimum of two values.
func Min[T Ordered](a, b T) T {
	if a < b {
		return a
	}

	return b
}

// Error logs the error and exits the program.
func Error(err error) {
	_, fn, line, _ := runtime.Caller(1)
	log.Fatalf("ERROR: %s:%d %v\n", fn, line, err)
}

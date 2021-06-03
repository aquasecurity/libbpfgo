package helpers

import (
	"debug/elf"
	"fmt"
)

// SymbolToOffset attempts to resolve a 'symbol' name within a specific
// 'section' of the binary found at 'path' to an offset. The offset
// can be used for attaching a u(ret)probe
func SymbolToOffset(path, section, symbol string) (uint32, error) {

	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("could not open elf file to resolve symbol offset: %v", err)
	}

	syms, err := f.Symbols()
	if err != nil {
		return 0, fmt.Errorf("could not open symbol section to resolve symbol offset: %v", err)
	}

	textSection := f.Section(section)
	if textSection == nil {
		return 0, fmt.Errorf("could not calculate start of text section in binary")
	}

	for i := range syms {
		if syms[i].Name == symbol {
			return uint32(syms[i].Value - textSection.Addr + textSection.Offset), nil
		}
	}
	return 0, fmt.Errorf("symbol not found")
}

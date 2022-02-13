package helpers

import (
	"debug/elf"
	"errors"
	"fmt"
)

// symbolToOffset attempts to resolve a 'symbol' name in the given binary to an offset.
// The offset can be used for attaching a u(ret)probe.
func symbolToOffset(symbol string, f *elf.File, syms []elf.Symbol) (uint32, error) {
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

			return uint32(syms[j].Value - executableSection.Addr + executableSection.Offset), nil
		}
	}

	return 0, errors.New("symbol not found")
}

// SymbolToOffset attempts to resolve a 'symbol' name in the binary found at
// 'path' to an offset. The offset can be used for attaching a u(ret)probe
func SymbolToOffset(path, symbol string) (uint32, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("could not open elf file to resolve symbol offset: %w", err)
	}

	syms, err := f.Symbols()
	if err != nil {
		return 0, fmt.Errorf("could not open symbol section to resolve symbol offset: %w", err)
	}

	return symbolToOffset(symbol, f, syms)
}

// DynamicSymbolToOffset attempts to resolve a dynamic 'symbol' name in the binary found at
// 'path' to an offset. The offset can be used for attaching a u(ret)probe
func DynamicSymbolToOffset(path, symbol string) (uint32, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("could not open elf file to resolve symbol offset: %w", err)
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("could not open dynamic symbol section to resolve symbol offset: %w", err)
	}

	return symbolToOffset(symbol, f, syms)
}

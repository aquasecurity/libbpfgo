package helpers

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

/*
 * The helpers in this file gives the ability to query kernel symbols.
 *
 * The KernelSymbolTable interface should query a map of all the kernel symbols with a key which is the kernel object owner and the name with under-case between them.
 * As such the query keys looks like [objectOwner_objectname{SymbolData}, objectOwner_objectname{SymbolData}, etc...]
 * The key schema is due to kernel symbols being able to have the same name or address which prevents being able to key the map with only one of them.
 */

const (
	kallsymsPath = "/proc/kallsyms"
)

type KernelSymbolTable interface {
	TextSegmentContains(addr uint64) (bool, error)
	GetSymbolByName(owner string, name string) (*KernelSymbol, error)
	GetSymbolByAddr(addr uint64) (*KernelSymbol, error)
	Refresh() error
}

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}

// errors

func SymbolNotFound(owner, name string) error {
	return fmt.Errorf("symbol not found: %s_%s", owner, name)
}
func SymbolNotFoundAtAddress(addr uint64) error {
	return fmt.Errorf("symbol not found at address: 0x%x", addr)
}

// general

func symbolKey(owner, name string) string {
	return owner + "_" + name
}

// parses ksymbol line file file. returns in order the symbols "type", "name", "order"
func parseSymbolLine(line []string) (string, string, string) {
	symbolType := strings.Clone(line[1])
	symbolName := strings.Clone(line[2])

	symbolOwner := "system"
	if len(line) > 3 {
		// When a symbol is contained in a kernel module, it will be specified
		// within square brackets, otherwise it's part of the system
		symbolOwner = strings.Clone(line[3])
		symbolOwner = strings.TrimPrefix(symbolOwner, "[")
		symbolOwner = strings.TrimSuffix(symbolOwner, "]")
	}
	return symbolType, symbolName, symbolOwner
}

// fullKernelSymbolTable

type fullKernelSymbolTable struct {
	symbolMap     map[string]*KernelSymbol
	symbolAddrMap map[uint64]*KernelSymbol
	textSegStart  uint64
	textSegEnd    uint64
}

/* NewKernelSymbolsMap initiates a kernel symbol map by parsing the /proc/kallsyms file.
 * Each line contains the symbol's address, segment type, name, module owner (which can be empty in case the symbol is owned by the system).
 * If memory is a concern, using this constructor can allocate up to ~130mb.
 * Note: the key of the map is the symbol owner and the symbol name (with undercase between them)
 */
func NewKernelSymbolsMap() (KernelSymbolTable, error) {
	k := fullKernelSymbolTable{}
	err := k.Refresh()

	return &k, err
}

// TextSegmentContains checks if a given address is in the kernel text segment
// by comparing it to the kernel text segment address boundaries
func (k *fullKernelSymbolTable) TextSegmentContains(addr uint64) (bool, error) {
	return addr >= k.textSegStart && addr < k.textSegEnd, nil
}

// GetSymbolByName returns a symbol by a given name and owner
func (k *fullKernelSymbolTable) GetSymbolByName(owner string, name string) (*KernelSymbol, error) {
	symbol, exist := k.symbolMap[symbolKey(owner, name)]
	if exist {
		return symbol, nil
	}
	return nil, SymbolNotFound(owner, name)
}

// GetSymbolByAddr returns a symbol by a given address
func (k *fullKernelSymbolTable) GetSymbolByAddr(addr uint64) (*KernelSymbol, error) {
	symbol, exist := k.symbolAddrMap[addr]
	if exist {
		return symbol, nil
	}
	return nil, SymbolNotFoundAtAddress(addr)
}

func (k *fullKernelSymbolTable) Refresh() error {
	k.symbolMap = make(map[string]*KernelSymbol)
	k.symbolAddrMap = make(map[uint64]*KernelSymbol)
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return fmt.Errorf("could not open /proc/kallsyms: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		// if the line is less than 3 words, we can't parse it (one or more
		// fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}

		symbolType, symbolName, symbolOwner := parseSymbolLine(line)

		symbolKey := symbolOwner + "_" + symbolName
		symbol := &KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
		k.symbolMap[symbolKey] = symbol
		k.symbolAddrMap[symbolAddr] = symbol
	}
	stext, err := k.GetSymbolByName("system", "_stext")
	if err != nil {
		return err
	}
	k.textSegStart = stext.Address
	etext, err := k.GetSymbolByName("system", "_etext")
	if err != nil {
		return err
	}
	k.textSegStart = etext.Address
	return nil
}

// lazyKernelSymbols
type lazyKernelSymbols struct {
	fileContent   []string
	symbolMap     map[string]*KernelSymbol
	symbolAddrMap map[uint64]*KernelSymbol
	textSegStart  uint64
	textSegEnd    uint64
}

// NewLazyKernelSymbolsMap will return a lazy implementation of the KernelSymbolTable
// The lazy implementation keeps a copy of the /proc/kallsyms file content and queries that
// copy on demand, instead of preparsing it.
// It keeps caches of previously found results.
func NewLazyKernelSymbolsMap() (KernelSymbolTable, error) {
	k := &lazyKernelSymbols{}
	err := k.Refresh()
	return k, err
}

func (k *lazyKernelSymbols) TextSegmentContains(addr uint64) (bool, error) {
	// query the segments if not queried yet
	if k.textSegEnd < k.textSegStart {
		stext, err := k.GetSymbolByName("system", "_stext")
		if err != nil {
			return false, err
		}
		k.textSegStart = stext.Address
		etext, err := k.GetSymbolByName("system", "_etext")
		if err != nil {
			return false, err
		}
		k.textSegEnd = etext.Address
	}
	return addr >= k.textSegStart && addr < k.textSegEnd, nil
}

func (k *lazyKernelSymbols) GetSymbolByName(owner string, name string) (*KernelSymbol, error) {
	key := symbolKey(owner, name)
	symbol, exist := k.symbolMap[key]
	if exist {
		return symbol, nil
	}
	for _, line := range k.fileContent {
		line := strings.Fields(line)
		// if the line is less than 3 words, we can't parse it (one or more fields missing)
		// if the searched owner isn't system and the line counter is less than 4 words, the line is irrelevant
		if len(line) < 3 || (owner != "system" && len(line) < 4) {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}

		symbolType, symbolName, symbolOwner := parseSymbolLine(line)

		if name == symbolName && owner == symbolOwner {
			symbolKey := symbolKey(symbolOwner, symbolName)
			symbol := &KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
			k.symbolMap[symbolKey] = symbol
			k.symbolAddrMap[symbolAddr] = symbol
			return symbol, nil
		}
	}
	return nil, SymbolNotFound(owner, name)
}

func (k *lazyKernelSymbols) GetSymbolByAddr(addr uint64) (*KernelSymbol, error) {
	symbol, exist := k.symbolAddrMap[addr]
	if exist {
		return symbol, nil
	}

	var (
		symbolAddr uint64
		err        error
	)

	fileLen := len(k.fileContent)
	found := false
	// kallsyms are almost sorted by address, start search with binary search
	i := sort.Search(fileLen, func(i int) bool {
		line := strings.Fields(k.fileContent[i])
		if len(line) < 3 {
			return false
		}
		symbolAddr, err = strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			return false
		}
		if symbolAddr == addr {
			found = true

			symbolType, symbolName, symbolOwner := parseSymbolLine(line)

			symbolKey := symbolKey(symbolOwner, symbolName)
			symbol = &KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
			k.symbolMap[symbolKey] = symbol
			k.symbolAddrMap[symbolAddr] = symbol
			return true
		}
		return symbolAddr > addr
	})

	if i < len(k.fileContent) && found {
		return symbol, nil
	}

	// symbols may be out of order near the end of the ksymbols, search linearly in reverse
	for i := fileLen - 1; i > 0; i-- {
		line := strings.Fields(k.fileContent[i])
		if len(line) < 3 {
			continue
		}
		symbolAddr, err = strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		if symbolAddr == addr {
			symbolType := strings.Clone(line[1])
			symbolName := strings.Clone(line[2])

			symbolOwner := "system"
			if len(line) > 3 {
				// When a symbol is contained in a kernel module, it will be specified
				// within square brackets, otherwise it's part of the system
				symbolOwner = strings.Clone(line[3])
				symbolOwner = strings.TrimPrefix(symbolOwner, "[")
				symbolOwner = strings.TrimSuffix(symbolOwner, "]")
			}

			symbolKey := symbolKey(symbolOwner, symbolName)
			symbol := &KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
			k.symbolMap[symbolKey] = symbol
			k.symbolAddrMap[symbolAddr] = symbol
			return symbol, nil
		}
	}
	return nil, SymbolNotFoundAtAddress(addr)
}

func (k *lazyKernelSymbols) Refresh() error {
	file, err := os.ReadFile(kallsymsPath)
	if err != nil {
		return fmt.Errorf("could not open /proc/kallsyms: %w", err)
	}
	fileLines := strings.Split(string(file), "\n")
	k.fileContent = fileLines
	k.symbolMap = make(map[string]*KernelSymbol)
	k.symbolAddrMap = make(map[uint64]*KernelSymbol)
	k.textSegStart = math.MaxUint64
	k.textSegEnd = 0

	return nil
}

// kept for benchmarking purpose
func (k *lazyKernelSymbols) getSymbolByAddrNotBinary(addr uint64) (*KernelSymbol, error) {
	symbol, exist := k.symbolAddrMap[addr]
	if exist {
		return symbol, nil
	}
	for _, line := range k.fileContent {
		line := strings.Fields(line)
		// if the line is less than 3 words, we can't parse it (one or more fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		if symbolAddr != addr {
			continue
		}

		symbolType, symbolName, symbolOwner := parseSymbolLine(line)

		symbolKey := symbolKey(symbolOwner, symbolName)
		symbol := &KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
		k.symbolMap[symbolKey] = symbol
		k.symbolAddrMap[symbolAddr] = symbol
		return symbol, nil
	}
	return nil, SymbolNotFoundAtAddress(addr)
}

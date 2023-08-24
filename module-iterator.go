package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

//
// BPFObjectIterator (Module Iterator)
//

// BPFObjectProgramIterator iterates over programs and maps in a BPF object
type BPFObjectIterator struct {
	m        *Module
	prevProg *BPFProg
	prevMap  *BPFMap
}

func (it *BPFObjectIterator) NextMap() *BPFMap {
	var startMap *C.struct_bpf_map
	if it.prevMap != nil && it.prevMap.bpfMap != nil {
		startMap = it.prevMap.bpfMap
	}

	m := C.bpf_object__next_map(it.m.obj, startMap)
	if m == nil {
		return nil
	}

	bpfMap := &BPFMap{
		bpfMap: m,
		module: it.m,
	}
	it.prevMap = bpfMap

	if !bpfMap.module.loaded {
		bpfMap.bpfMapLow = &BPFMapLow{
			fd:   -1,
			info: &BPFMapInfo{},
		}

		return bpfMap
	}

	fd := bpfMap.FileDescriptor()
	info, err := GetMapInfoByFD(fd)
	if err != nil {
		return nil
	}

	bpfMap.bpfMapLow = &BPFMapLow{
		fd:   fd,
		info: info,
	}

	return bpfMap
}

func (it *BPFObjectIterator) NextProgram() *BPFProg {
	var startProg *C.struct_bpf_program
	if it.prevProg != nil && it.prevProg.prog != nil {
		startProg = it.prevProg.prog
	}

	p := C.bpf_object__next_program(it.m.obj, startProg)
	if p == nil {
		return nil
	}
	cName := C.bpf_program__name(p)

	prog := &BPFProg{
		name:   C.GoString(cName),
		prog:   p,
		module: it.m,
	}
	it.prevProg = prog
	return prog
}

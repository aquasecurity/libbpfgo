package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// BPFMapCreateOpts mirrors the C structure bpf_map_create_opts
type BPFMapCreateOpts struct {
	Size                  uint64
	BtfFD                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxValueTypeID uint32
	InnerMapFD            uint32
	MapFlags              uint32
	MapExtra              uint64
	NumaNode              uint32
	MapIfIndex            uint32
}

func bpfMapCreateOptsToC(createOpts *BPFMapCreateOpts) *C.struct_bpf_map_create_opts {
	if createOpts == nil {
		return nil
	}
	opts := C.struct_bpf_map_create_opts{}
	opts.sz = C.ulong(createOpts.Size)
	opts.btf_fd = C.uint(createOpts.BtfFD)
	opts.btf_key_type_id = C.uint(createOpts.BtfKeyTypeID)
	opts.btf_value_type_id = C.uint(createOpts.BtfValueTypeID)
	opts.btf_vmlinux_value_type_id = C.uint(createOpts.BtfVmlinuxValueTypeID)
	opts.inner_map_fd = C.uint(createOpts.InnerMapFD)
	opts.map_flags = C.uint(createOpts.MapFlags)
	opts.map_extra = C.ulonglong(createOpts.MapExtra)
	opts.numa_node = C.uint(createOpts.NumaNode)
	opts.map_ifindex = C.uint(createOpts.MapIfIndex)

	return &opts
}

// CreateMap creates a BPF map from userspace. This can be used for populating
// BPF array of maps or hash of maps. However, this function uses a low-level
// libbpf API; maps created in this way do not conform to libbpf map formats,
// and therefore do not have access to libbpf high level bpf_map__* APIS
// which causes different behavior from maps created in the kernel side code
//
// See usage of `bpf_map_create()` in kernel selftests for more info
func CreateMap(mapType MapType, mapName string, keySize, valueSize, maxEntries int, opts *BPFMapCreateOpts) (*BPFMap, error) {
	cs := C.CString(mapName)
	fdOrError := C.bpf_map_create(uint32(mapType), cs, C.uint(keySize), C.uint(valueSize), C.uint(maxEntries), bpfMapCreateOptsToC(opts))
	C.free(unsafe.Pointer(cs))
	if fdOrError < 0 {
		return nil, fmt.Errorf("could not create map: %w", syscall.Errno(-fdOrError))
	}

	return &BPFMap{
		name:   mapName,
		fd:     fdOrError,
		module: nil,
		bpfMap: nil,
	}, nil
}

type BPFMap struct {
	name   string
	bpfMap *C.struct_bpf_map
	fd     C.int
	module *Module
}

type MapType uint32

const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
	MapTypeProgArray
	MapTypePerfEventArray
	MapTypePerCPUHash
	MapTypePerCPUArray
	MapTypeStackTrace
	MapTypeCgroupArray
	MapTypeLRUHash
	MapTypeLRUPerCPUHash
	MapTypeLPMTrie
	MapTypeArrayOfMaps
	MapTypeHashOfMaps
	MapTypeDevMap
	MapTypeSockMap
	MapTypeCPUMap
	MapTypeXSKMap
	MapTypeSockHash
	MapTypeCgroupStorage
	MapTypeReusePortSockArray
	MapTypePerCPUCgroupStorage
	MapTypeQueue
	MapTypeStack
	MapTypeSKStorage
	MapTypeDevmapHash
	MapTypeStructOps
	MapTypeRingbuf
	MapTypeInodeStorage
	MapTypeTaskStorage
	MapTypeBloomFilter
)

type MapFlag uint32

const (
	MapFlagUpdateAny     MapFlag = iota // create new element or update existing
	MapFlagUpdateNoExist                // create new element if it didn't exist
	MapFlagUpdateExist                  // update existing element
	MapFlagFLock                        // spin_lock-ed map_lookup/map_update
)

func (m MapType) String() string {
	x := map[MapType]string{
		MapTypeUnspec:              "BPF_MAP_TYPE_UNSPEC",
		MapTypeHash:                "BPF_MAP_TYPE_HASH",
		MapTypeArray:               "BPF_MAP_TYPE_ARRAY",
		MapTypeProgArray:           "BPF_MAP_TYPE_PROG_ARRAY",
		MapTypePerfEventArray:      "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
		MapTypePerCPUHash:          "BPF_MAP_TYPE_PERCPU_HASH",
		MapTypePerCPUArray:         "BPF_MAP_TYPE_PERCPU_ARRAY",
		MapTypeStackTrace:          "BPF_MAP_TYPE_STACK_TRACE",
		MapTypeCgroupArray:         "BPF_MAP_TYPE_CGROUP_ARRAY",
		MapTypeLRUHash:             "BPF_MAP_TYPE_LRU_HASH",
		MapTypeLRUPerCPUHash:       "BPF_MAP_TYPE_LRU_PERCPU_HASH",
		MapTypeLPMTrie:             "BPF_MAP_TYPE_LPM_TRIE",
		MapTypeArrayOfMaps:         "BPF_MAP_TYPE_ARRAY_OF_MAPS",
		MapTypeHashOfMaps:          "BPF_MAP_TYPE_HASH_OF_MAPS",
		MapTypeDevMap:              "BPF_MAP_TYPE_DEVMAP",
		MapTypeSockMap:             "BPF_MAP_TYPE_SOCKMAP",
		MapTypeCPUMap:              "BPF_MAP_TYPE_CPUMAP",
		MapTypeXSKMap:              "BPF_MAP_TYPE_XSKMAP",
		MapTypeSockHash:            "BPF_MAP_TYPE_SOCKHASH",
		MapTypeCgroupStorage:       "BPF_MAP_TYPE_CGROUP_STORAGE",
		MapTypeReusePortSockArray:  "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
		MapTypePerCPUCgroupStorage: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
		MapTypeQueue:               "BPF_MAP_TYPE_QUEUE",
		MapTypeStack:               "BPF_MAP_TYPE_STACK",
		MapTypeSKStorage:           "BPF_MAP_TYPE_SK_STORAGE",
		MapTypeDevmapHash:          "BPF_MAP_TYPE_DEVMAP_HASH",
		MapTypeStructOps:           "BPF_MAP_TYPE_STRUCT_OPS",
		MapTypeRingbuf:             "BPF_MAP_TYPE_RINGBUF",
		MapTypeInodeStorage:        "BPF_MAP_TYPE_INODE_STORAGE",
		MapTypeTaskStorage:         "BPF_MAP_TYPE_TASK_STORAGE",
		MapTypeBloomFilter:         "BPF_MAP_TYPE_BLOOM_FILTER",
	}
	return x[m]
}

func (b *BPFMap) Name() string {
	cs := C.bpf_map__name(b.bpfMap)
	if cs == nil {
		return ""
	}
	s := C.GoString(cs)
	return s
}

func (b *BPFMap) Type() MapType {
	return MapType(C.bpf_map__type(b.bpfMap))
}

// SetType is used to set the type of a bpf map that isn't associated
// with a file descriptor already. If the map is already associated
// with a file descriptor the libbpf API will return error code EBUSY
func (b *BPFMap) SetType(mapType MapType) error {
	errC := C.bpf_map__set_type(b.bpfMap, C.enum_bpf_map_type(int(mapType)))
	if errC != 0 {
		return fmt.Errorf("could not set bpf map type: %w", syscall.Errno(-errC))
	}
	return nil
}

func (b *BPFMap) Pin(pinPath string) error {
	path := C.CString(pinPath)
	ret := C.bpf_map__pin(b.bpfMap, path)
	C.free(unsafe.Pointer(path))
	if ret != 0 {
		return fmt.Errorf("failed to pin map %s to path %s: %w", b.name, pinPath, syscall.Errno(-ret))
	}
	return nil
}

func (b *BPFMap) Unpin(pinPath string) error {
	path := C.CString(pinPath)
	ret := C.bpf_map__unpin(b.bpfMap, path)
	C.free(unsafe.Pointer(path))
	if ret != 0 {
		return fmt.Errorf("failed to unpin map %s from path %s: %w", b.name, pinPath, syscall.Errno(-ret))
	}
	return nil
}

func (b *BPFMap) SetPinPath(pinPath string) error {
	path := C.CString(pinPath)
	ret := C.bpf_map__set_pin_path(b.bpfMap, path)
	C.free(unsafe.Pointer(path))
	if ret != 0 {
		return fmt.Errorf("failed to set pin for map %s to path %s: %w", b.name, pinPath, syscall.Errno(-ret))
	}
	return nil
}

// Resize changes the map's capacity to maxEntries.
// It should be called after the module was initialized but
// prior to it being loaded with BPFLoadObject.
// Note: for ring buffer and perf buffer, maxEntries is the
// capacity in bytes.
func (b *BPFMap) Resize(maxEntries uint32) error {
	ret := C.bpf_map__set_max_entries(b.bpfMap, C.uint(maxEntries))
	if ret != 0 {
		return fmt.Errorf("failed to resize map %s to %v: %w", b.name, maxEntries, syscall.Errno(-ret))
	}
	return nil
}

// GetMaxEntries returns the map's capacity.
// Note: for ring buffer and perf buffer, maxEntries is the
// capacity in bytes.
func (b *BPFMap) GetMaxEntries() uint32 {
	maxEntries := C.bpf_map__max_entries(b.bpfMap)
	return uint32(maxEntries)
}

func (b *BPFMap) FileDescriptor() int {
	return int(C.bpf_map__fd(b.bpfMap))
}

// Deprecated: use BPFMap.FileDescriptor() instead.
func (b *BPFMap) GetFd() int {
	return b.FileDescriptor()
}

// Deprecated: use BPFMap.Name() instead.
func (b *BPFMap) GetName() string {
	return b.Name()
}

func (b *BPFMap) GetModule() *Module {
	return b.module
}

func (b *BPFMap) PinPath() string {
	return C.GoString(C.bpf_map__pin_path(b.bpfMap))
}

// Deprecated: use BPFMap.PinPath() instead.
func (b *BPFMap) GetPinPath() string {
	return b.PinPath()
}

func (b *BPFMap) IsPinned() bool {
	isPinned := C.bpf_map__is_pinned(b.bpfMap)
	return isPinned == C.bool(true)
}

func (b *BPFMap) KeySize() int {
	return int(C.bpf_map__key_size(b.bpfMap))
}

func (b *BPFMap) ValueSize() int {
	return int(C.bpf_map__value_size(b.bpfMap))
}

func (b *BPFMap) SetValueSize(size uint32) error {
	ret := C.bpf_map__set_value_size(b.bpfMap, C.uint(size))
	if ret != 0 {
		return fmt.Errorf("could not set map value size: %w", syscall.Errno(-ret))
	}
	return nil
}

// GetValue takes a pointer to the key which is stored in the map.
// It returns the associated value as a slice of bytes.
// All basic types, and structs are supported as keys.
//
// NOTE: Slices and arrays are also supported but special care
// should be taken as to take a reference to the first element
// in the slice or array instead of the slice/array itself, as to
// avoid undefined behavior.
func (b *BPFMap) GetValue(key unsafe.Pointer) ([]byte, error) {
	value := make([]byte, b.ValueSize())
	valuePtr := unsafe.Pointer(&value[0])

	ret, errC := C.bpf_map_lookup_elem(b.fd, key, valuePtr)
	if ret != 0 {
		return nil, fmt.Errorf("failed to lookup value %v in map %s: %w", key, b.name, errC)
	}
	return value, nil
}

func (b *BPFMap) GetValueFlags(key unsafe.Pointer, flags MapFlag) ([]byte, error) {
	value := make([]byte, b.ValueSize())
	valuePtr := unsafe.Pointer(&value[0])

	errC := C.bpf_map_lookup_elem_flags(b.fd, key, valuePtr, C.ulonglong(flags))
	if errC != 0 {
		return nil, fmt.Errorf("failed to lookup value %v in map %s: %w", key, b.name, syscall.Errno(-errC))
	}
	return value, nil
}

// GetValueReadInto is like GetValue, except it allows the caller to pass in
// a pointer to the slice of bytes that the value would be read into from the
// map.
// This is useful for reading from maps with variable sizes, especially
// per-cpu arrays and hash maps where the size of each value depends on the
// number of CPUs
func (b *BPFMap) GetValueReadInto(key unsafe.Pointer, value *[]byte) error {
	valuePtr := unsafe.Pointer(&(*value)[0])
	ret := C.bpf_map__lookup_elem(b.bpfMap, key, C.ulong(b.KeySize()), valuePtr, C.ulong(len(*value)), 0)
	if ret != 0 {
		return fmt.Errorf("failed to lookup value %v in map %s: %w", key, b.name, syscall.Errno(-ret))
	}
	return nil
}

func (b *BPFMap) setInitialValue(value unsafe.Pointer) error {
	sz := b.ValueSize()
	ret := C.bpf_map__set_initial_value(b.bpfMap, value, C.ulong(sz))
	if ret != 0 {
		return fmt.Errorf("failed to set inital value for map %s: %w", b.name, syscall.Errno(-ret))
	}
	return nil
}

func (b *BPFMap) getInitialValue() []byte {
	value := make([]byte, b.ValueSize())
	valuePtr := unsafe.Pointer(&value[0])
	C.get_internal_map_init_value(b.bpfMap, valuePtr)
	return value
}

// BPFMapBatchOpts mirrors the C structure bpf_map_batch_opts.
type BPFMapBatchOpts struct {
	Sz        uint64
	ElemFlags uint64
	Flags     uint64
}

func bpfMapBatchOptsToC(batchOpts *BPFMapBatchOpts) *C.struct_bpf_map_batch_opts {
	if batchOpts == nil {
		return nil
	}
	opts := C.struct_bpf_map_batch_opts{}
	opts.sz = C.ulong(batchOpts.Sz)
	opts.elem_flags = C.ulonglong(batchOpts.ElemFlags)
	opts.flags = C.ulonglong(batchOpts.Flags)

	return &opts
}

// GetValueBatch allows for batch lookups of multiple keys from the map.
//
// The first argument, keys, is a pointer to an array or slice of keys which will be populated with the keys returned from this operation.
// It returns the associated values as a slice of slices of bytes.
//
// This API allows for batch lookups of multiple keys, potentially in steps over multiple iterations. For example,
// you provide the last key seen (or nil) for the startKey, and the first key to start the next iteration with in nextKey.
// Once the first iteration is complete you can provide the last key seen in the previous iteration as the startKey for the next iteration
// and repeat until nextKey is nil.
//
// The last argument, count, is the number of keys to lookup. The kernel will update it with the count of the elements that were
// retrieved.
//
// The API can return partial results even though an -1 is returned. In this case, errno will be set to `ENOENT` and the values slice and count
// will be filled in with the elements that were read. See the inline comment in `GetValueAndDeleteBatch` for more context.
func (b *BPFMap) GetValueBatch(keys unsafe.Pointer, startKey, nextKey unsafe.Pointer, count uint32) ([][]byte, error) {
	var (
		values    = make([]byte, b.ValueSize()*int(count))
		valuesPtr = unsafe.Pointer(&values[0])
		countC    = C.uint(count)
	)

	opts := &BPFMapBatchOpts{
		Sz:        uint64(unsafe.Sizeof(BPFMapBatchOpts{})),
		ElemFlags: C.BPF_ANY,
		Flags:     C.BPF_ANY,
	}

	ret, errC := C.bpf_map_lookup_batch(b.fd, startKey, nextKey, keys, valuesPtr, &countC, bpfMapBatchOptsToC(opts))
	processed := uint32(countC)

	if ret != 0 && errC != syscall.ENOENT {
		return nil, fmt.Errorf("failed to batch get value %v in map %s: ret %d (err: %s)", keys, b.name, ret, errC)
	}

	// Either some or all entries were read.
	// ret = -1 && errno == syscall.ENOENT indicates a partial read.
	return collectBatchValues(values, processed, b.ValueSize()), nil
}

// GetValueAndDeleteBatch allows for batch lookup and deletion of elements where each element is deleted after being retrieved from the map.
//
// The first argument, keys, is a pointer to an array or slice of keys which will be populated with the keys returned from this operation.
// It returns the associated values as a slice of slices of bytes.
//
// This API allows for batch lookups and deletion of multiple keys, potentially in steps over multiple iterations. For example,
// you provide the last key seen (or nil) for the startKey, and the first key to start the next iteration with in nextKey.
// Once the first iteration is complete you can provide the last key seen in the previous iteration as the startKey for the next iteration
// and repeat until nextKey is nil.
//
// The last argument, count, is the number of keys to lookup and delete. The kernel will update it with the count of the elements that were
// retrieved and deleted.
//
// The API can return partial results even though an -1 is returned. In this case, errno will be set to `ENOENT` and the values slice and count
// will be filled in with the elements that were read. See the comment below for more context.
func (b *BPFMap) GetValueAndDeleteBatch(keys, startKey, nextKey unsafe.Pointer, count uint32) ([][]byte, error) {
	var (
		values    = make([]byte, b.ValueSize()*int(count))
		valuesPtr = unsafe.Pointer(&values[0])
		countC    = C.uint(count)
	)

	opts := &BPFMapBatchOpts{
		Sz:        uint64(unsafe.Sizeof(BPFMapBatchOpts{})),
		ElemFlags: C.BPF_ANY,
		Flags:     C.BPF_ANY,
	}

	// Before libbpf 1.0 (without LIBBPF_STRICT_DIRECT_ERRS), the return value
	// and errno are not modified [1]. On error, we will get a return value of
	// -1 and errno will be set accordingly with most BPF calls.
	//
	// The batch APIs are a bit different in which they can return an error, but
	// depending on the errno code, it might mean a complete error (nothing was
	// done) or a partial success (some elements were processed).
	//
	// - On complete sucess, it will return 0, and errno won't be set.
	// - On partial sucess, it will return -1, and errno will be set to ENOENT.
	// - On error, it will return -1, and an errno different to ENOENT.
	//
	// [1] https://github.com/libbpf/libbpf/blob/b69f8ee93ef6aa3518f8fbfd9d1df6c2c84fd08f/src/libbpf_internal.h#L496
	ret, errC := C.bpf_map_lookup_and_delete_batch(
		b.fd,
		startKey,
		nextKey,
		keys,
		valuesPtr,
		&countC,
		bpfMapBatchOptsToC(opts))

	processed := uint32(countC)

	if ret != 0 && errC != syscall.ENOENT {
		// ret = -1 && errno == syscall.ENOENT indicates a partial read and delete.
		return nil, fmt.Errorf("failed to batch lookup and delete values %v in map %s: ret %d (err: %s)", keys, b.name, ret, errC)
	}

	// Either some or all entries were read and deleted.
	parsedVals := collectBatchValues(values, processed, b.ValueSize())
	return parsedVals, nil
}

func collectBatchValues(values []byte, count uint32, valueSize int) [][]byte {
	var value []byte
	var collected [][]byte
	for i := 0; i < int(count*uint32(valueSize)); i += valueSize {
		value = values[i : i+valueSize]
		collected = append(collected, value)
	}
	return collected
}

// UpdateBatch updates multiple elements in the map by specified keys and their corresponding values.
//
// The first argument, keys, is a pointer to an array or slice of keys which will be updated using the second argument, values.
// It returns the associated error if any occurred.
//
// The last argument, count, is the number of keys to update. Passing an argument that greater than the number of keys
// in the map will cause the function to return a syscall.EPERM as an error.
func (b *BPFMap) UpdateBatch(keys, values unsafe.Pointer, count uint32) error {
	countC := C.uint(count)

	opts := BPFMapBatchOpts{
		Sz:        uint64(unsafe.Sizeof(BPFMapBatchOpts{})),
		ElemFlags: C.BPF_ANY,
		Flags:     C.BPF_ANY,
	}

	errC := C.bpf_map_update_batch(b.fd, keys, values, &countC, bpfMapBatchOptsToC(&opts))
	if errC != 0 {
		sc := syscall.Errno(-errC)
		if sc != syscall.EFAULT {
			if uint32(countC) != count {
				return fmt.Errorf("failed to update ALL elements in map %s, updated (%d/%d): %w", b.name, uint32(countC), count, sc)
			}
		}
		return fmt.Errorf("failed to batch update elements in map %s: %w", b.name, syscall.Errno(-errC))
	}

	return nil
}

// DeleteKeyBatch allows for batch deletion of multiple elements in the map.
//
// `count` number of keys will be deleted from the map. Passing an argument that greater than the number of keys
// in the map will cause the function to delete fewer keys than requested. See the inline comment in
// `GetValueAndDeleteBatch` for more context.
func (b *BPFMap) DeleteKeyBatch(keys unsafe.Pointer, count uint32) error {
	countC := C.uint(count)

	opts := &BPFMapBatchOpts{
		Sz:        uint64(unsafe.Sizeof(BPFMapBatchOpts{})),
		ElemFlags: C.BPF_ANY,
		Flags:     C.BPF_ANY,
	}

	ret, errC := C.bpf_map_delete_batch(b.fd, keys, &countC, bpfMapBatchOptsToC(opts))

	if ret != 0 && errC != syscall.ENOENT {
		return fmt.Errorf("failed to batch delete keys %v in map %s: ret %d (err: %s)", keys, b.name, ret, errC)
	}

	// ret = -1 && errno == syscall.ENOENT indicates a partial deletion.
	return nil
}

// DeleteKey takes a pointer to the key which is stored in the map.
// It removes the key and associated value from the BPFMap.
// All basic types, and structs are supported as keys.
//
// NOTE: Slices and arrays are also supported but special care
// should be taken as to take a reference to the first element
// in the slice or array instead of the slice/array itself, as to
// avoid undefined behavior.
func (b *BPFMap) DeleteKey(key unsafe.Pointer) error {
	ret, errC := C.bpf_map_delete_elem(b.fd, key)
	if ret != 0 {
		return fmt.Errorf("failed to get lookup key %d from map %s: %w", key, b.name, errC)
	}
	return nil
}

// Update takes a pointer to a key and a value to associate it with in
// the BPFMap. The unsafe.Pointer should be taken on a reference to the
// underlying datatype. All basic types, and structs are supported
//
// NOTE: Slices and arrays are supported but references should be passed
// to the first element in the slice or array.
//
// For example:
//
// key := 1
// value := []byte{'a', 'b', 'c'}
// keyPtr := unsafe.Pointer(&key)
// valuePtr := unsafe.Pointer(&value[0])
// bpfmap.Update(keyPtr, valuePtr)
func (b *BPFMap) Update(key, value unsafe.Pointer) error {
	return b.UpdateValueFlags(key, value, MapFlagUpdateAny)
}

func (b *BPFMap) UpdateValueFlags(key, value unsafe.Pointer, flags MapFlag) error {
	errC := C.bpf_map_update_elem(b.fd, key, value, C.ulonglong(flags))
	if errC != 0 {
		return fmt.Errorf("failed to update map %s: %w", b.name, syscall.Errno(-errC))
	}
	return nil
}

// BPFMapIterator iterates over keys in a BPF map
type BPFMapIterator struct {
	b    *BPFMap
	err  error
	prev []byte
	next []byte
}

func (b *BPFMap) Iterator() *BPFMapIterator {
	return &BPFMapIterator{
		b:    b,
		prev: nil,
		next: nil,
	}
}

func (it *BPFMapIterator) Next() bool {
	if it.err != nil {
		return false
	}

	prevPtr := unsafe.Pointer(nil)
	if it.next != nil {
		prevPtr = unsafe.Pointer(&it.next[0])
	}

	next := make([]byte, it.b.KeySize())
	nextPtr := unsafe.Pointer(&next[0])

	errC, err := C.bpf_map_get_next_key(it.b.fd, prevPtr, nextPtr)
	if errno, ok := err.(syscall.Errno); errC == -2 && ok && errno == C.ENOENT {
		return false
	}
	if err != nil {
		it.err = err
		return false
	}

	it.prev = it.next
	it.next = next

	return true
}

// Key returns the current key value of the iterator, if the most recent call to Next returned true.
// The slice is valid only until the next call to Next.
func (it *BPFMapIterator) Key() []byte {
	return it.next
}

// Err returns the last error that ocurred while table.Iter or iter.Next
func (it *BPFMapIterator) Err() error {
	return it.err
}

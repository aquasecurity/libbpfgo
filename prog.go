package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

//
// BPFProg
//

type BPFProg struct {
	name       string
	prog       *C.struct_bpf_program
	module     *Module
	pinnedPath string
}

func (p *BPFProg) FileDescriptor() int {
	return int(C.bpf_program__fd(p.prog))
}

// Deprecated: use BPFProg.FileDescriptor() instead.
func (p *BPFProg) GetFd() int {
	return p.FileDescriptor()
}

func (p *BPFProg) Pin(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %s: %v", path, err)
	}

	cs := C.CString(absPath)
	ret := C.bpf_program__pin(p.prog, cs)
	C.free(unsafe.Pointer(cs))
	if ret != 0 {
		return fmt.Errorf("failed to pin program %s to %s: %w", p.name, path, syscall.Errno(-ret))
	}
	p.pinnedPath = absPath
	return nil
}

func (p *BPFProg) Unpin(path string) error {
	cs := C.CString(path)
	ret := C.bpf_program__unpin(p.prog, cs)
	C.free(unsafe.Pointer(cs))
	if ret != 0 {
		return fmt.Errorf("failed to unpin program %s to %s: %w", p.name, path, syscall.Errno(-ret))
	}
	p.pinnedPath = ""
	return nil
}

func (p *BPFProg) GetModule() *Module {
	return p.module
}

func (p *BPFProg) Name() string {
	return C.GoString(C.bpf_program__name(p.prog))
}

// Deprecated: use BPFProg.Name() instead.
func (p *BPFProg) GetName() string {
	return p.Name()
}

func (p *BPFProg) SectionName() string {
	return C.GoString(C.bpf_program__section_name(p.prog))
}

// Deprecated: use BPFProg.SectionName() instead.
func (p *BPFProg) GetSectionName() string {
	return p.SectionName()
}

func (p *BPFProg) PinPath() string {
	return p.pinnedPath // There's no LIBBPF_API for bpf program
}

// Deprecated: use BPFProg.PinPath() instead.
func (p *BPFProg) GetPinPath() string {
	return p.PinPath()
}

func (p *BPFProg) GetType() BPFProgType {
	return BPFProgType(C.bpf_program__type(p.prog))
}

func (p *BPFProg) SetAutoload(autoload bool) error {
	cbool := C.bool(autoload)
	ret := C.bpf_program__set_autoload(p.prog, cbool)
	if ret != 0 {
		return fmt.Errorf("failed to set bpf program autoload: %w", syscall.Errno(-ret))
	}
	return nil
}

// AttachGeneric is used to attach the BPF program using autodetection
// for the attach target. You can specify the destination in BPF code
// via the SEC() such as `SEC("fentry/some_kernel_func")`
func (p *BPFProg) AttachGeneric() (*BPFLink, error) {
	link, errno := C.bpf_program__attach(p.prog)
	if link == nil {
		return nil, fmt.Errorf("failed to attach program: %w", errno)
	}
	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  Tracing,
		eventName: fmt.Sprintf("tracing-%s", p.name),
	}
	return bpfLink, nil
}

// SetAttachTarget can be used to specify the program and/or function to attach
// the BPF program to. To attach to a kernel function specify attachProgFD as 0
func (p *BPFProg) SetAttachTarget(attachProgFD int, attachFuncName string) error {
	cs := C.CString(attachFuncName)
	ret := C.bpf_program__set_attach_target(p.prog, C.int(attachProgFD), cs)
	C.free(unsafe.Pointer(cs))
	if ret != 0 {
		return fmt.Errorf("failed to set attach target for program %s %s %w", p.name, attachFuncName, syscall.Errno(-ret))
	}
	return nil
}

func (p *BPFProg) SetProgramType(progType BPFProgType) {
	C.bpf_program__set_type(p.prog, C.enum_bpf_prog_type(int(progType)))
}

func (p *BPFProg) SetAttachType(attachType BPFAttachType) {
	C.bpf_program__set_expected_attach_type(p.prog, C.enum_bpf_attach_type(int(attachType)))
}

// getCgroupDirFD returns a file descriptor for a given cgroup2 directory path
func getCgroupDirFD(cgroupV2DirPath string) (int, error) {
	// revive:disable
	const (
		O_DIRECTORY int = syscall.O_DIRECTORY
		O_RDONLY    int = syscall.O_RDONLY
	)
	// revive:enable
	fd, err := syscall.Open(cgroupV2DirPath, O_DIRECTORY|O_RDONLY, 0)
	if fd < 0 {
		return 0, fmt.Errorf("failed to open cgroupv2 directory path %s: %w", cgroupV2DirPath, err)
	}
	return fd, nil
}

// AttachCgroup attaches the BPFProg to a cgroup described by given fd.
func (p *BPFProg) AttachCgroup(cgroupV2DirPath string) (*BPFLink, error) {
	cgroupDirFD, err := getCgroupDirFD(cgroupV2DirPath)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(cgroupDirFD)

	link, errno := C.bpf_program__attach_cgroup(p.prog, C.int(cgroupDirFD))
	if link == nil {
		return nil, fmt.Errorf("failed to attach cgroup on cgroupv2 %s to program %s: %w", cgroupV2DirPath, p.name, errno)
	}

	// dirName will be used in bpfLink.eventName. eventName follows a format
	// convention and is used to better identify link types and what they are
	// linked with in case of errors or similar needs. Having eventName as:
	// cgroup-progName-/sys/fs/cgroup/unified/ would look weird so replace it
	// to be cgroup-progName-sys-fs-cgroup-unified instead.
	dirName := strings.ReplaceAll(cgroupV2DirPath[1:], "/", "-")
	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  Cgroup,
		eventName: fmt.Sprintf("cgroup-%s-%s", p.name, dirName),
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

// AttachCgroupLegacy attaches the BPFProg to a cgroup described by the given
// fd. It first tries to use the most recent attachment method and, if that does
// not work, instead of failing, it tries the legacy way: to attach the cgroup
// eBPF program without previously creating a link. This allows attaching cgroup
// eBPF ingress/egress in older kernels. Note: the first attempt error message
// is filtered out inside libbpf_print_fn() as it is actually a feature probe
// attempt as well.
//
// Related kernel commit: https://github.com/torvalds/linux/commit/af6eea57437a
func (p *BPFProg) AttachCgroupLegacy(cgroupV2DirPath string, attachType BPFAttachType) (*BPFLink, error) {
	bpfLink, err := p.AttachCgroup(cgroupV2DirPath)
	if err == nil {
		return bpfLink, nil
	}
	// Try the legacy attachment method before fully failing
	cgroupDirFD, err := getCgroupDirFD(cgroupV2DirPath)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(cgroupDirFD)
	progFD := C.bpf_program__fd(p.prog)
	ret := C.cgo_bpf_prog_attach_cgroup_legacy(progFD, C.int(cgroupDirFD), C.int(attachType))
	if ret < 0 {
		return nil, fmt.Errorf("failed to attach (legacy) program %s to cgroupv2 %s", p.name, cgroupV2DirPath)
	}
	dirName := strings.ReplaceAll(cgroupV2DirPath[1:], "/", "-")

	bpfLinkLegacy := &bpfLinkLegacy{
		attachType: attachType,
		cgroupDir:  cgroupV2DirPath,
	}
	fakeBpfLink := &BPFLink{
		link:      nil, // detach/destroy made with progfd
		prog:      p,
		eventName: fmt.Sprintf("cgroup-%s-%s", p.name, dirName),
		// info bellow needed for detach (there isn't a real ebpf link)
		linkType: CgroupLegacy,
		legacy:   bpfLinkLegacy,
	}
	return fakeBpfLink, nil
}

// DetachCgroupLegacy detaches the BPFProg from a cgroup described by the given
// fd. This is needed because in legacy attachment there is no BPFLink, just a
// fake one (kernel did not support it, nor libbpf). This function should be
// called by the (*BPFLink)->Destroy() function, since BPFLink is emulated (so
// users don´t need to distinguish between regular and legacy cgroup
// detachments).
func (p *BPFProg) DetachCgroupLegacy(cgroupV2DirPath string, attachType BPFAttachType) error {
	cgroupDirFD, err := getCgroupDirFD(cgroupV2DirPath)
	if err != nil {
		return err
	}
	defer syscall.Close(cgroupDirFD)
	progFD := C.bpf_program__fd(p.prog)
	ret := C.cgo_bpf_prog_detach_cgroup_legacy(progFD, C.int(cgroupDirFD), C.int(attachType))
	if ret < 0 {
		return fmt.Errorf("failed to detach (legacy) program %s from cgroupv2 %s", p.name, cgroupV2DirPath)
	}
	return nil
}

func (p *BPFProg) AttachXDP(deviceName string) (*BPFLink, error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find device by name %s: %w", deviceName, err)
	}
	link, errno := C.bpf_program__attach_xdp(p.prog, C.int(iface.Index))
	if link == nil {
		return nil, fmt.Errorf("failed to attach xdp on device %s to program %s: %w", deviceName, p.name, errno)
	}

	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  XDP,
		eventName: fmt.Sprintf("xdp-%s-%s", p.name, deviceName),
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BPFProg) AttachTracepoint(category, name string) (*BPFLink, error) {
	tpCategory := C.CString(category)
	tpName := C.CString(name)
	link, errno := C.bpf_program__attach_tracepoint(p.prog, tpCategory, tpName)
	C.free(unsafe.Pointer(tpCategory))
	C.free(unsafe.Pointer(tpName))
	if link == nil {
		return nil, fmt.Errorf("failed to attach tracepoint %s to program %s: %w", name, p.name, errno)
	}

	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  Tracepoint,
		eventName: name,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BPFProg) AttachRawTracepoint(tpEvent string) (*BPFLink, error) {
	cs := C.CString(tpEvent)
	link, errno := C.bpf_program__attach_raw_tracepoint(p.prog, cs)
	C.free(unsafe.Pointer(cs))
	if link == nil {
		return nil, fmt.Errorf("failed to attach raw tracepoint %s to program %s: %w", tpEvent, p.name, errno)
	}

	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  RawTracepoint,
		eventName: tpEvent,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BPFProg) AttachLSM() (*BPFLink, error) {
	link, errno := C.bpf_program__attach_lsm(p.prog)
	if link == nil {
		return nil, fmt.Errorf("failed to attach lsm to program %s: %w", p.name, errno)
	}

	bpfLink := &BPFLink{
		link:     link,
		prog:     p,
		linkType: LSM,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BPFProg) AttachPerfEvent(fd int) (*BPFLink, error) {
	link, errno := C.bpf_program__attach_perf_event(p.prog, C.int(fd))
	if link == nil {
		return nil, fmt.Errorf("failed to attach perf event to program %s: %w", p.name, errno)
	}

	bpfLink := &BPFLink{
		link:     link,
		prog:     p,
		linkType: PerfEvent,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

// this API should be used for kernels > 4.17
func (p *BPFProg) AttachKprobe(kp string) (*BPFLink, error) {
	return doAttachKprobe(p, kp, false)
}

// this API should be used for kernels > 4.17
func (p *BPFProg) AttachKretprobe(kp string) (*BPFLink, error) {
	return doAttachKprobe(p, kp, true)
}

func doAttachKprobe(prog *BPFProg, kp string, isKretprobe bool) (*BPFLink, error) {
	cs := C.CString(kp)
	cbool := C.bool(isKretprobe)
	link, errno := C.bpf_program__attach_kprobe(prog.prog, cbool, cs)
	C.free(unsafe.Pointer(cs))
	if link == nil {
		return nil, fmt.Errorf("failed to attach %s k(ret)probe to program %s: %w", kp, prog.name, errno)
	}

	kpType := Kprobe
	if isKretprobe {
		kpType = Kretprobe
	}

	bpfLink := &BPFLink{
		link:      link,
		prog:      prog,
		linkType:  kpType,
		eventName: kp,
	}
	prog.module.links = append(prog.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BPFProg) AttachNetns(networkNamespacePath string) (*BPFLink, error) {
	fd, err := syscall.Open(networkNamespacePath, syscall.O_RDONLY, 0)
	if fd < 0 {
		return nil, fmt.Errorf("failed to open network namespace path %s: %w", networkNamespacePath, err)
	}
	link, errno := C.bpf_program__attach_netns(p.prog, C.int(fd))
	if link == nil {
		return nil, fmt.Errorf("failed to attach network namespace on %s to program %s: %w", networkNamespacePath, p.name, errno)
	}

	// fileName will be used in bpfLink.eventName. eventName follows a format
	// convention and is used to better identify link types and what they are
	// linked with in case of errors or similar needs. Having eventName as:
	// netns-progName-/proc/self/ns/net would look weird so replace it
	// to be netns-progName-proc-self-ns-net instead.
	fileName := strings.ReplaceAll(networkNamespacePath[1:], "/", "-")
	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  Netns,
		eventName: fmt.Sprintf("netns-%s-%s", p.name, fileName),
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

type IterOpts struct {
	MapFd           int
	CgroupIterOrder BPFCgroupIterOrder
	CgroupFd        int
	CgroupId        uint64
	Tid             int
	Pid             int
	PidFd           int
}

func (p *BPFProg) AttachIter(opts IterOpts) (*BPFLink, error) {
	mapFd := C.uint(opts.MapFd)
	cgroupIterOrder := uint32(opts.CgroupIterOrder)
	cgroupFd := C.uint(opts.CgroupFd)
	cgroupId := C.ulonglong(opts.CgroupId)
	tid := C.uint(opts.Tid)
	pid := C.uint(opts.Pid)
	pidFd := C.uint(opts.PidFd)
	cOpts, errno := C.cgo_bpf_iter_attach_opts_new(mapFd, cgroupIterOrder, cgroupFd, cgroupId, tid, pid, pidFd)
	if cOpts == nil {
		return nil, fmt.Errorf("failed to create iter_attach_opts to program %s: %w", p.name, errno)
	}
	defer C.cgo_bpf_iter_attach_opts_free(cOpts)

	link, errno := C.bpf_program__attach_iter(p.prog, cOpts)
	if link == nil {
		return nil, fmt.Errorf("failed to attach iter to program %s: %w", p.name, errno)
	}
	eventName := fmt.Sprintf("iter-%s-%d", p.name, opts.MapFd)
	bpfLink := &BPFLink{
		link:      link,
		prog:      p,
		linkType:  Iter,
		eventName: eventName,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

// AttachUprobe attaches the BPFProgram to entry of the symbol in the library or binary at 'path'
// which can be relative or absolute. A pid can be provided to attach to, or -1 can be specified
// to attach to all processes
func (p *BPFProg) AttachUprobe(pid int, path string, offset uint32) (*BPFLink, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	return doAttachUprobe(p, false, pid, absPath, offset)
}

// AttachURetprobe attaches the BPFProgram to exit of the symbol in the library or binary at 'path'
// which can be relative or absolute. A pid can be provided to attach to, or -1 can be specified
// to attach to all processes
func (p *BPFProg) AttachURetprobe(pid int, path string, offset uint32) (*BPFLink, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	return doAttachUprobe(p, true, pid, absPath, offset)
}

func doAttachUprobe(prog *BPFProg, isUretprobe bool, pid int, path string, offset uint32) (*BPFLink, error) {
	retCBool := C.bool(isUretprobe)
	pidCint := C.int(pid)
	pathCString := C.CString(path)
	offsetCsizet := C.size_t(offset)

	link, errno := C.bpf_program__attach_uprobe(prog.prog, retCBool, pidCint, pathCString, offsetCsizet)
	C.free(unsafe.Pointer(pathCString))
	if link == nil {
		return nil, fmt.Errorf("failed to attach u(ret)probe to program %s:%d with pid %d: %w ", path, offset, pid, errno)
	}

	upType := Uprobe
	if isUretprobe {
		upType = Uretprobe
	}

	bpfLink := &BPFLink{
		link:      link,
		prog:      prog,
		linkType:  upType,
		eventName: fmt.Sprintf("%s:%d:%d", path, pid, offset),
	}
	return bpfLink, nil
}

// AttachGenericFD attaches the BPFProgram to a targetFd at the specified attachType hook.
func (p *BPFProg) AttachGenericFD(targetFd int, attachType BPFAttachType, flags AttachFlag) error {
	progFd := C.bpf_program__fd(p.prog)
	errC := C.bpf_prog_attach(progFd, C.int(targetFd), C.enum_bpf_attach_type(int(attachType)), C.uint(uint(flags)))
	if errC < 0 {
		return fmt.Errorf("failed to attach: %w", syscall.Errno(-errC))
	}
	return nil
}

// DetachGenericFD detaches the BPFProgram associated with the targetFd at the hook specified by attachType.
func (p *BPFProg) DetachGenericFD(targetFd int, attachType BPFAttachType) error {
	progFd := C.bpf_program__fd(p.prog)
	errC := C.bpf_prog_detach2(progFd, C.int(targetFd), C.enum_bpf_attach_type(int(attachType)))
	if errC < 0 {
		return fmt.Errorf("failed to detach: %w", syscall.Errno(-errC))
	}
	return nil
}

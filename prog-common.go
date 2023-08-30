package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

//
// BPFProgType
//

// BPFProgType is an enum as defined in https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BPFProgType uint32

const (
	BPFProgTypeUnspec BPFProgType = iota
	BPFProgTypeSocketFilter
	BPFProgTypeKprobe
	BPFProgTypeSchedCls
	BPFProgTypeSchedAct
	BPFProgTypeTracepoint
	BPFProgTypeXdp
	BPFProgTypePerfEvent
	BPFProgTypeCgroupSkb
	BPFProgTypeCgroupSock
	BPFProgTypeLwtIn
	BPFProgTypeLwtOut
	BPFProgTypeLwtXmit
	BPFProgTypeSockOps
	BPFProgTypeSkSkb
	BPFProgTypeCgroupDevice
	BPFProgTypeSkMsg
	BPFProgTypeRawTracepoint
	BPFProgTypeCgroupSockAddr
	BPFProgTypeLwtSeg6Local
	BPFProgTypeLircMode2
	BPFProgTypeSkReuseport
	BPFProgTypeFlowDissector
	BPFProgTypeCgroupSysctl
	BPFProgTypeRawTracepointWritable
	BPFProgTypeCgroupSockopt
	BPFProgTypeTracing
	BPFProgTypeStructOps
	BPFProgTypeExt
	BPFProgTypeLsm
	BPFProgTypeSkLookup
	BPFProgTypeSyscall
)

// Deprecated: Convert type directly instead.
func (t BPFProgType) Value() uint64 { return uint64(t) }

var bpfProgTypeToString = map[BPFProgType]string{
	BPFProgTypeUnspec:                "BPF_PROG_TYPE_UNSPEC",
	BPFProgTypeSocketFilter:          "BPF_PROG_TYPE_SOCKET_FILTER",
	BPFProgTypeKprobe:                "BPF_PROG_TYPE_KPROBE",
	BPFProgTypeSchedCls:              "BPF_PROG_TYPE_SCHED_CLS",
	BPFProgTypeSchedAct:              "BPF_PROG_TYPE_SCHED_ACT",
	BPFProgTypeTracepoint:            "BPF_PROG_TYPE_TRACEPOINT",
	BPFProgTypeXdp:                   "BPF_PROG_TYPE_XDP",
	BPFProgTypePerfEvent:             "BPF_PROG_TYPE_PERF_EVENT",
	BPFProgTypeCgroupSkb:             "BPF_PROG_TYPE_CGROUP_SKB",
	BPFProgTypeCgroupSock:            "BPF_PROG_TYPE_CGROUP_SOCK",
	BPFProgTypeLwtIn:                 "BPF_PROG_TYPE_LWT_IN",
	BPFProgTypeLwtOut:                "BPF_PROG_TYPE_LWT_OUT",
	BPFProgTypeLwtXmit:               "BPF_PROG_TYPE_LWT_XMIT",
	BPFProgTypeSockOps:               "BPF_PROG_TYPE_SOCK_OPS",
	BPFProgTypeSkSkb:                 "BPF_PROG_TYPE_SK_SKB",
	BPFProgTypeCgroupDevice:          "BPF_PROG_TYPE_CGROUP_DEVICE",
	BPFProgTypeSkMsg:                 "BPF_PROG_TYPE_SK_MSG",
	BPFProgTypeRawTracepoint:         "BPF_PROG_TYPE_RAW_TRACEPOINT",
	BPFProgTypeCgroupSockAddr:        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	BPFProgTypeLwtSeg6Local:          "BPF_PROG_TYPE_LWT_SEG6LOCAL",
	BPFProgTypeLircMode2:             "BPF_PROG_TYPE_LIRC_MODE2",
	BPFProgTypeSkReuseport:           "BPF_PROG_TYPE_SK_REUSEPORT",
	BPFProgTypeFlowDissector:         "BPF_PROG_TYPE_FLOW_DISSECTOR",
	BPFProgTypeCgroupSysctl:          "BPF_PROG_TYPE_CGROUP_SYSCTL",
	BPFProgTypeRawTracepointWritable: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	BPFProgTypeCgroupSockopt:         "BPF_PROG_TYPE_CGROUP_SOCKOPT",
	BPFProgTypeTracing:               "BPF_PROG_TYPE_TRACING",
	BPFProgTypeStructOps:             "BPF_PROG_TYPE_STRUCT_OPS",
	BPFProgTypeExt:                   "BPF_PROG_TYPE_EXT",
	BPFProgTypeLsm:                   "BPF_PROG_TYPE_LSM",
	BPFProgTypeSkLookup:              "BPF_PROG_TYPE_SK_LOOKUP",
	BPFProgTypeSyscall:               "BPF_PROG_TYPE_SYSCALL",
}

func (t BPFProgType) String() string {
	str, ok := bpfProgTypeToString[t]
	if !ok {
		// BPFProgTypeUnspec must exist in bpfProgTypeToString to avoid infinite recursion.
		return BPFProgTypeUnspec.String()
	}

	return str
}

//
// BPFAttachType
//

type BPFAttachType uint32

const (
	BPFAttachTypeCgroupInetIngress BPFAttachType = iota
	BPFAttachTypeCgroupInetEgress
	BPFAttachTypeCgroupInetSockCreate
	BPFAttachTypeCgroupSockOps
	BPFAttachTypeSKSKBStreamParser
	BPFAttachTypeSKSKBStreamVerdict
	BPFAttachTypeCgroupDevice
	BPFAttachTypeSKMSGVerdict
	BPFAttachTypeCgroupInet4Bind
	BPFAttachTypeCgroupInet6Bind
	BPFAttachTypeCgroupInet4Connect
	BPFAttachTypeCgroupInet6Connect
	BPFAttachTypeCgroupInet4PostBind
	BPFAttachTypeCgroupInet6PostBind
	BPFAttachTypeCgroupUDP4SendMsg
	BPFAttachTypeCgroupUDP6SendMsg
	BPFAttachTypeLircMode2
	BPFAttachTypeFlowDissector
	BPFAttachTypeCgroupSysctl
	BPFAttachTypeCgroupUDP4RecvMsg
	BPFAttachTypeCgroupUDP6RecvMsg
	BPFAttachTypeCgroupGetSockOpt
	BPFAttachTypeCgroupSetSockOpt
	BPFAttachTypeTraceRawTP
	BPFAttachTypeTraceFentry
	BPFAttachTypeTraceFexit
	BPFAttachTypeModifyReturn
	BPFAttachTypeLSMMac
	BPFAttachTypeTraceIter
	BPFAttachTypeCgroupInet4GetPeerName
	BPFAttachTypeCgroupInet6GetPeerName
	BPFAttachTypeCgroupInet4GetSockName
	BPFAttachTypeCgroupInet6GetSockName
	BPFAttachTypeXDPDevMap
	BPFAttachTypeCgroupInetSockRelease
	BPFAttachTypeXDPCPUMap
	BPFAttachTypeSKLookup
	BPFAttachTypeXDP
	BPFAttachTypeSKSKBVerdict
	BPFAttachTypeSKReusePortSelect
	BPFAttachTypeSKReusePortSelectorMigrate
	BPFAttachTypePerfEvent
	BPFAttachTypeTraceKprobeMulti
)

//
// BPFCgroupIterOrder
//

type BPFCgroupIterOrder uint32

const (
	BPFIterOrderUnspec BPFCgroupIterOrder = iota
	BPFIterSelfOnly
	BPFIterDescendantsPre
	BPFIterDescendantsPost
	BPFIterAncestorsUp
)

//
// AttachFlag
//

type AttachFlag uint32

const (
	BPFFNone          AttachFlag = 0
	BPFFAllowOverride AttachFlag = C.BPF_F_ALLOW_OVERRIDE
	BPFFAllowMulti    AttachFlag = C.BPF_F_ALLOW_MULTI
	BPFFReplace       AttachFlag = C.BPF_F_REPLACE
)

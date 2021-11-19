package helpers

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type SystemFunctionArgument interface {
	fmt.Stringer
	Value() uint64
}

const (
	// These values are copied from uapi/linux/sched.h
	CLONE_VM             CloneFlagArgument = 0x00000100
	CLONE_FS             CloneFlagArgument = 0x00000200
	CLONE_FILES          CloneFlagArgument = 0x00000400
	CLONE_SIGHAND        CloneFlagArgument = 0x00000800
	CLONE_PIDFD          CloneFlagArgument = 0x00001000
	CLONE_PTRACE         CloneFlagArgument = 0x00002000
	CLONE_VFORK          CloneFlagArgument = 0x00004000
	CLONE_PARENT         CloneFlagArgument = 0x00008000
	CLONE_THREAD         CloneFlagArgument = 0x00010000
	CLONE_NEWNS          CloneFlagArgument = 0x00020000
	CLONE_SYSVSEM        CloneFlagArgument = 0x00040000
	CLONE_SETTLS         CloneFlagArgument = 0x00080000
	CLONE_PARENT_SETTID  CloneFlagArgument = 0x00100000
	CLONE_CHILD_CLEARTID CloneFlagArgument = 0x00200000
	CLONE_DETACHED       CloneFlagArgument = 0x00400000
	CLONE_UNTRACED       CloneFlagArgument = 0x00800000
	CLONE_CHILD_SETTID   CloneFlagArgument = 0x01000000
	CLONE_NEWCGROUP      CloneFlagArgument = 0x02000000
	CLONE_NEWUTS         CloneFlagArgument = 0x04000000
	CLONE_NEWIPC         CloneFlagArgument = 0x08000000
	CLONE_NEWUSER        CloneFlagArgument = 0x10000000
	CLONE_NEWPID         CloneFlagArgument = 0x20000000
	CLONE_NEWNET         CloneFlagArgument = 0x40000000
	CLONE_IO             CloneFlagArgument = 0x80000000

	// These values are copied from uapi/asm-generic/fcntl.h
	O_ACCMODE   OpenFlagArgument = 00000003
	O_RDONLY    OpenFlagArgument = 00000000
	O_WRONLY    OpenFlagArgument = 00000001
	O_RDWR      OpenFlagArgument = 00000002
	O_CREAT     OpenFlagArgument = 00000100
	O_EXCL      OpenFlagArgument = 00000200
	O_NOCTTY    OpenFlagArgument = 00000400
	O_TRUNC     OpenFlagArgument = 00001000
	O_APPEND    OpenFlagArgument = 00002000
	O_NONBLOCK  OpenFlagArgument = 00004000
	O_DSYNC     OpenFlagArgument = 00010000
	O_SYNC      OpenFlagArgument = 04010000
	O_ASYNC     OpenFlagArgument = 020000
	FASYNC      OpenFlagArgument = 00020000
	O_DIRECT    OpenFlagArgument = 00040000
	O_LARGEFILE OpenFlagArgument = 00100000
	O_DIRECTORY OpenFlagArgument = 00200000
	O_NOFOLLOW  OpenFlagArgument = 00400000
	O_NOATIME   OpenFlagArgument = 01000000
	O_CLOEXEC   OpenFlagArgument = 02000000
	O_PATH      OpenFlagArgument = 040000000
	O_TMPFILE   OpenFlagArgument = 020000000

	F_OK AccessFlagArgument = 0
	X_OK AccessFlagArgument = 1
	W_OK AccessFlagArgument = 2
	R_OK AccessFlagArgument = 4

	AT_SYMLINK_NOFOLLOW   ExecFlagArgument = 0x100
	AT_EACCESS            ExecFlagArgument = 0x200
	AT_REMOVEDIR          ExecFlagArgument = 0x200
	AT_SYMLINK_FOLLOW     ExecFlagArgument = 0x400
	AT_NO_AUTOMOUNT       ExecFlagArgument = 0x800
	AT_EMPTY_PATH         ExecFlagArgument = 0x1000
	AT_STATX_SYNC_TYPE    ExecFlagArgument = 0x6000
	AT_STATX_SYNC_AS_STAT ExecFlagArgument = 0x0000
	AT_STATX_FORCE_SYNC   ExecFlagArgument = 0x2000
	AT_STATX_DONT_SYNC    ExecFlagArgument = 0x4000
	AT_RECURSIVE          ExecFlagArgument = 0x8000

	PTRACE_TRACEME              PtraceRequestArgument = 0
	PTRACE_PEEKTEXT             PtraceRequestArgument = 1
	PTRACE_PEEKDATA             PtraceRequestArgument = 2
	PTRACE_PEEKUSER             PtraceRequestArgument = 3
	PTRACE_POKETEXT             PtraceRequestArgument = 4
	PTRACE_POKEDATA             PtraceRequestArgument = 5
	PTRACE_POKEUSER             PtraceRequestArgument = 6
	PTRACE_CONT                 PtraceRequestArgument = 7
	PTRACE_KILL                 PtraceRequestArgument = 8
	PTRACE_SINGLESTEP           PtraceRequestArgument = 9
	PTRACE_GETREGS              PtraceRequestArgument = 12
	PTRACE_SETREGS              PtraceRequestArgument = 13
	PTRACE_GETFPREGS            PtraceRequestArgument = 14
	PTRACE_SETFPREGS            PtraceRequestArgument = 15
	PTRACE_ATTACH               PtraceRequestArgument = 16
	PTRACE_DETACH               PtraceRequestArgument = 17
	PTRACE_GETFPXREGS           PtraceRequestArgument = 18
	PTRACE_SETFPXREGS           PtraceRequestArgument = 19
	PTRACE_SYSCALL              PtraceRequestArgument = 24
	PTRACE_SETOPTIONS           PtraceRequestArgument = 0x4200
	PTRACE_GETEVENTMSG          PtraceRequestArgument = 0x4201
	PTRACE_GETSIGINFO           PtraceRequestArgument = 0x4202
	PTRACE_SETSIGINFO           PtraceRequestArgument = 0x4203
	PTRACE_GETREGSET            PtraceRequestArgument = 0x4204
	PTRACE_SETREGSET            PtraceRequestArgument = 0x4205
	PTRACE_SEIZE                PtraceRequestArgument = 0x4206
	PTRACE_INTERRUPT            PtraceRequestArgument = 0x4207
	PTRACE_LISTEN               PtraceRequestArgument = 0x4208
	PTRACE_PEEKSIGINFO          PtraceRequestArgument = 0x4209
	PTRACE_GETSIGMASK           PtraceRequestArgument = 0x420a
	PTRACE_SETSIGMASK           PtraceRequestArgument = 0x420b
	PTRACE_SECCOMP_GET_FILTER   PtraceRequestArgument = 0x420c
	PTRACE_SECCOMP_GET_METADATA PtraceRequestArgument = 0x420d

	SOCK_STREAM    SocketTypeArgument = 1
	SOCK_DGRAM     SocketTypeArgument = 2
	SOCK_RAW       SocketTypeArgument = 3
	SOCK_RDM       SocketTypeArgument = 4
	SOCK_SEQPACKET SocketTypeArgument = 5
	SOCK_DCCP      SocketTypeArgument = 6
	SOCK_PACKET    SocketTypeArgument = 10
	SOCK_NONBLOCK  SocketTypeArgument = 000004000
	SOCK_CLOEXEC   SocketTypeArgument = 002000000

	S_IFSOCK InodeModeArgument = 0140000
	S_IFLNK  InodeModeArgument = 0120000
	S_IFREG  InodeModeArgument = 0100000
	S_IFBLK  InodeModeArgument = 060000
	S_IFDIR  InodeModeArgument = 040000
	S_IFCHR  InodeModeArgument = 020000
	S_IFIFO  InodeModeArgument = 010000
	S_IRWXU  InodeModeArgument = 00700
	S_IRUSR  InodeModeArgument = 00400
	S_IWUSR  InodeModeArgument = 00200
	S_IXUSR  InodeModeArgument = 00100
	S_IRWXG  InodeModeArgument = 00070
	S_IRGRP  InodeModeArgument = 00040
	S_IWGRP  InodeModeArgument = 00020
	S_IXGRP  InodeModeArgument = 00010
	S_IRWXO  InodeModeArgument = 00007
	S_IROTH  InodeModeArgument = 00004
	S_IWOTH  InodeModeArgument = 00002
	S_IXOTH  InodeModeArgument = 00001

	PROT_READ      MmapProtArgument = 0x1
	PROT_WRITE     MmapProtArgument = 0x2
	PROT_EXEC      MmapProtArgument = 0x4
	PROT_SEM       MmapProtArgument = 0x8
	PROT_NONE      MmapProtArgument = 0x0
	PROT_GROWSDOWN MmapProtArgument = 0x01000000
	PROT_GROWSUP   MmapProtArgument = 0x02000000
)

const (
	CAP_CHOWN CapabilityFlagArgument = iota
	CAP_DAC_OVERRIDE
	CAP_DAC_READ_SEARCH
	CAP_FOWNER
	CAP_FSETID
	CAP_KILL
	CAP_SETGID
	CAP_SETUID
	CAP_SETPCAP
	CAP_LINUX_IMMUTABLE
	CAP_NET_BIND_SERVICE
	CAP_NET_BROADCAST
	CAP_NET_ADMIN
	CAP_NET_RAW
	CAP_IPC_LOCK
	CAP_IPC_OWNER
	CAP_SYS_MODULE
	CAP_SYS_RAWIO
	CAP_SYS_CHROOT
	CAP_SYS_PTRACE
	CAP_SYS_PACCT
	CAP_SYS_ADMIN
	CAP_SYS_BOOT
	CAP_SYS_NICE
	CAP_SYS_RESOURCE
	CAP_SYS_TIME
	CAP_SYS_TTY_CONFIG
	CAP_MKNOD
	CAP_LEASE
	CAP_AUDIT_WRITE
	CAP_AUDIT_CONTROL
	CAP_SETFCAP
	CAP_MAC_OVERRIDE
	CAP_MAC_ADMIN
	CAP_SYSLOG
	CAP_WAKE_ALARM
	CAP_BLOCK_SUSPEND
	CAP_AUDIT_READ
)

const (
	PR_SET_PDEATHSIG PrctlFlagArgument = iota + 1
	PR_GET_PDEATHSIG
	PR_GET_DUMPABLE
	PR_SET_DUMPABLE
	PR_GET_UNALIGN
	PR_SET_UNALIGN
	PR_GET_KEEPCAPS
	PR_SET_KEEPCAPS
	PR_GET_FPEMU
	PR_SET_FPEMU
	PR_GET_FPEXC
	PR_SET_FPEXC
	PR_GET_TIMING
	PR_SET_TIMING
	PR_SET_NAME
	PR_GET_NAME
	PR_GET_ENDIAN
	PR_SET_ENDIAN
	PR_GET_SECCOMP
	PR_SET_SECCOMP
	PR_CAPBSET_READ
	PR_CAPBSET_DROP
	PR_GET_TSC
	PR_SET_TSC
	PR_GET_SECUREBITS
	PR_SET_SECUREBITS
	PR_SET_TIMERSLACK
	PR_GET_TIMERSLACK
	PR_TASK_PERF_EVENTS_DISABLE
	PR_TASK_PERF_EVENTS_ENABLE
	PR_MCE_KILL
	PR_MCE_KILL_GET
	PR_SET_MM
	PR_SET_CHILD_SUBREAPER
	PR_GET_CHILD_SUBREAPER
	PR_SET_NO_NEW_PRIVS
	PR_GET_NO_NEW_PRIVS
	PR_GET_TID_ADDRESS
	PR_SET_THP_DISABLE
	PR_GET_THP_DISABLE
	PR_MPX_ENABLE_MANAGEMENT
	PR_MPX_DISABLE_MANAGEMENT
	PR_SET_FP_MODE
	PR_GET_FP_MODE
	PR_CAP_AMBIENT
	PR_SVE_SET_VL
	PR_SVE_GET_VL
	PR_GET_SPECULATION_CTRL
	PR_SET_SPECULATION_CTRL
	PR_PAC_RESET_KEYS
	PR_SET_TAGGED_ADDR_CTRL
	PR_GET_TAGGED_ADDR_CTRL
)

const (
	BPF_MAP_CREATE BPFCommandArgument = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	BPF_MAP_FREEZE
	BPF_BTF_GET_NEXT_ID
	BPF_MAP_LOOKUP_BATCH
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	BPF_MAP_UPDATE_BATCH
	BPF_MAP_DELETE_BATCH
	BPF_LINK_CREATE
	BPF_LINK_UPDATE
	BPF_LINK_GET_FD_BY_ID
	BPF_LINK_GET_NEXT_ID
	BPF_ENABLE_STATS
	BPF_ITER_CREATE
	BPF_LINK_DETACH
)

const (
	AF_UNSPEC SocketDomainArgument = iota
	AF_UNIX
	AF_INET
	AF_AX25
	AF_IPX
	AF_APPLETALK
	AF_NETROM
	AF_BRIDGE
	AF_ATMPVC
	AF_X25
	AF_INET6
	AF_ROSE
	AF_DECnet
	AF_NETBEUI
	AF_SECURITY
	AF_KEY
	AF_NETLINK
	AF_PACKET
	AF_ASH
	AF_ECONET
	AF_ATMSVC
	AF_RDS
	AF_SNA
	AF_IRDA
	AF_PPPOX
	AF_WANPIPE
	AF_LLC
	AF_IB
	AF_MPLS
	AF_CAN
	AF_TIPC
	AF_BLUETOOTH
	AF_IUCV
	AF_RXRPC
	AF_ISDN
	AF_PHONET
	AF_IEEE802154
	AF_CAIF
	AF_ALG
	AF_NFC
	AF_VSOCK
	AF_KCM
	AF_QIPCRTR
	AF_SMC
	AF_XDP
)

// OptionAreContainedInArgument checks whether the argument (rawArgument)
// contains all of the 'options' such as with flags passed to the clone flag.
// This function takes an arbitrary number of SystemCallArguments.It will
// only return true if each and every option is present in rawArgument.
// Typically linux syscalls have multiple options specified in a single
// argument via bitmasks = which this function checks for.
func OptionAreContainedInArgument(rawArgument SystemFunctionArgument, options ...SystemFunctionArgument) bool {
	var isPresent = true
	for _, option := range options {
		isPresent = isPresent && (option.Value()&rawArgument.Value() == option.Value())
	}
	return isPresent
}

type CloneFlagArgument uint64

func (c CloneFlagArgument) Value() uint64 { return uint64(c) }

func (c CloneFlagArgument) String() string {
	var f []string
	if OptionAreContainedInArgument(c, CLONE_VM) {
		f = append(f, "CLONE_VM")
	}
	if OptionAreContainedInArgument(c, CLONE_FS) {
		f = append(f, "CLONE_FS")
	}
	if OptionAreContainedInArgument(c, CLONE_FILES) {
		f = append(f, "CLONE_FILES")
	}
	if OptionAreContainedInArgument(c, CLONE_SIGHAND) {
		f = append(f, "CLONE_SIGHAND")
	}
	if OptionAreContainedInArgument(c, CLONE_PIDFD) {
		f = append(f, "CLONE_PIDFD")
	}
	if OptionAreContainedInArgument(c, CLONE_PTRACE) {
		f = append(f, "CLONE_PTRACE")
	}
	if OptionAreContainedInArgument(c, CLONE_VFORK) {
		f = append(f, "CLONE_VFORK")
	}
	if OptionAreContainedInArgument(c, CLONE_PARENT) {
		f = append(f, "CLONE_PARENT")
	}
	if OptionAreContainedInArgument(c, CLONE_THREAD) {
		f = append(f, "CLONE_THREAD")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWNS) {
		f = append(f, "CLONE_NEWNS")
	}
	if OptionAreContainedInArgument(c, CLONE_SYSVSEM) {
		f = append(f, "CLONE_SYSVSEM")
	}
	if OptionAreContainedInArgument(c, CLONE_SETTLS) {
		f = append(f, "CLONE_SETTLS")
	}
	if OptionAreContainedInArgument(c, CLONE_PARENT_SETTID) {
		f = append(f, "CLONE_PARENT_SETTID")
	}
	if OptionAreContainedInArgument(c, CLONE_CHILD_CLEARTID) {
		f = append(f, "CLONE_CHILD_CLEARTID")
	}
	if OptionAreContainedInArgument(c, CLONE_DETACHED) {
		f = append(f, "CLONE_DETACHED")
	}
	if OptionAreContainedInArgument(c, CLONE_UNTRACED) {
		f = append(f, "CLONE_UNTRACED")
	}
	if OptionAreContainedInArgument(c, CLONE_CHILD_SETTID) {
		f = append(f, "CLONE_CHILD_SETTID")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWCGROUP) {
		f = append(f, "CLONE_NEWCGROUP")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWUTS) {
		f = append(f, "CLONE_NEWUTS")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWIPC) {
		f = append(f, "CLONE_NEWIPC")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWUSER) {
		f = append(f, "CLONE_NEWUSER")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWPID) {
		f = append(f, "CLONE_NEWPID")
	}
	if OptionAreContainedInArgument(c, CLONE_NEWNET) {
		f = append(f, "CLONE_NEWNET")
	}
	if OptionAreContainedInArgument(c, CLONE_IO) {
		f = append(f, "CLONE_IO")
	}
	if len(f) == 0 {
		f = append(f, "0")
	}

	return strings.Join(f, "|")
}

type OpenFlagArgument uint64

func (o OpenFlagArgument) Value() uint64 { return uint64(o) }

// String parses the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func (o OpenFlagArgument) String() string {
	var f []string

	// access mode
	switch {
	case OptionAreContainedInArgument(o, O_WRONLY):
		f = append(f, "O_WRONLY")
	case OptionAreContainedInArgument(o, O_RDWR):
		f = append(f, "O_RDWR")
	default:
		f = append(f, "O_RDONLY")
	}

	// file creation and status flags
	if OptionAreContainedInArgument(o, O_CREAT) {
		f = append(f, "O_CREAT")
	}
	if OptionAreContainedInArgument(o, O_EXCL) {
		f = append(f, "O_EXCL")
	}
	if OptionAreContainedInArgument(o, O_NOCTTY) {
		f = append(f, "O_NOCTTY")
	}
	if OptionAreContainedInArgument(o, O_TRUNC) {
		f = append(f, "O_TRUNC")
	}
	if OptionAreContainedInArgument(o, O_APPEND) {
		f = append(f, "O_APPEND")
	}
	if OptionAreContainedInArgument(o, O_NONBLOCK) {
		f = append(f, "O_NONBLOCK")
	}
	if OptionAreContainedInArgument(o, O_SYNC) {
		f = append(f, "O_SYNC")
	}
	if OptionAreContainedInArgument(o, O_ASYNC) {
		f = append(f, "O_ASYNC")
	}
	if OptionAreContainedInArgument(o, O_LARGEFILE) {
		f = append(f, "O_LARGEFILE")
	}
	if OptionAreContainedInArgument(o, O_DIRECTORY) {
		f = append(f, "O_DIRECTORY")
	}
	if OptionAreContainedInArgument(o, O_NOFOLLOW) {
		f = append(f, "O_NOFOLLOW")
	}
	if OptionAreContainedInArgument(o, O_CLOEXEC) {
		f = append(f, "O_CLOEXEC")
	}
	if OptionAreContainedInArgument(o, O_DIRECT) {
		f = append(f, "O_DIRECT")
	}
	if OptionAreContainedInArgument(o, O_NOATIME) {
		f = append(f, "O_NOATIME")
	}
	if OptionAreContainedInArgument(o, O_PATH) {
		f = append(f, "O_PATH")
	}
	if OptionAreContainedInArgument(o, O_TMPFILE) {
		f = append(f, "O_TMPFILE")
	}

	return strings.Join(f, "|")
}

type AccessFlagArgument uint64

func (a AccessFlagArgument) Value() uint64 { return uint64(a) }

// String parses the mode from the `access` system call
// http://man7.org/linux/man-pages/man2/access.2.html
func (a AccessFlagArgument) String() string {
	var f []string
	if a == 0x0 {
		f = append(f, "F_OK")
	} else {
		if OptionAreContainedInArgument(a, R_OK) {
			f = append(f, "R_OK")
		}
		if OptionAreContainedInArgument(a, W_OK) {
			f = append(f, "W_OK")
		}
		if OptionAreContainedInArgument(a, X_OK) {
			f = append(f, "X_OK")
		}
	}
	return strings.Join(f, "|")
}

type ExecFlagArgument uint64

func (e ExecFlagArgument) Value() uint64 { return uint64(e) }

func (e ExecFlagArgument) String() string {
	var f []string
	if OptionAreContainedInArgument(e, AT_EMPTY_PATH) {
		f = append(f, "AT_EMPTY_PATH")
	}
	if OptionAreContainedInArgument(e, AT_SYMLINK_NOFOLLOW) {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if OptionAreContainedInArgument(e, AT_EACCESS) {
		f = append(f, "AT_EACCESS")
	}
	if OptionAreContainedInArgument(e, AT_REMOVEDIR) {
		f = append(f, "AT_REMOVEDIR")
	}
	if OptionAreContainedInArgument(e, AT_NO_AUTOMOUNT) {
		f = append(f, "AT_NO_AUTOMOUNT")
	}
	if OptionAreContainedInArgument(e, AT_STATX_SYNC_TYPE) {
		f = append(f, "AT_STATX_SYNC_TYPE")
	}
	if OptionAreContainedInArgument(e, AT_STATX_FORCE_SYNC) {
		f = append(f, "AT_STATX_FORCE_SYNC")
	}
	if OptionAreContainedInArgument(e, AT_STATX_DONT_SYNC) {
		f = append(f, "AT_STATX_DONT_SYNC")
	}
	if OptionAreContainedInArgument(e, AT_RECURSIVE) {
		f = append(f, "AT_RECURSIVE")
	}
	if len(f) == 0 {
		f = append(f, "0")
	}

	return strings.Join(f, "|")
}

type CapabilityFlagArgument uint64

func (c CapabilityFlagArgument) Value() uint64 { return uint64(c) }

// String parses the `capability` bitmask argument of the
// `cap_capable` function include/uapi/linux/capability.h
func (c CapabilityFlagArgument) String() string {
	var capabilities = map[CapabilityFlagArgument]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
	}

	var res string

	if capName, ok := capabilities[c]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(c))
	}

	return res
}

type PrctlFlagArgument uint64

func (p PrctlFlagArgument) Value() uint64 { return uint64(p) }

// String parses the `option` argument of the `prctl` syscall
// http://man7.org/linux/man-pages/man2/prctl.2.html
func (p PrctlFlagArgument) String() string {
	var prctlOptions = map[PrctlFlagArgument]string{
		1:  "PR_SET_PDEATHSIG",
		2:  "PR_GET_PDEATHSIG",
		3:  "PR_GET_DUMPABLE",
		4:  "PR_SET_DUMPABLE",
		5:  "PR_GET_UNALIGN",
		6:  "PR_SET_UNALIGN",
		7:  "PR_GET_KEEPCAPS",
		8:  "PR_SET_KEEPCAPS",
		9:  "PR_GET_FPEMU",
		10: "PR_SET_FPEMU",
		11: "PR_GET_FPEXC",
		12: "PR_SET_FPEXC",
		13: "PR_GET_TIMING",
		14: "PR_SET_TIMING",
		15: "PR_SET_NAME",
		16: "PR_GET_NAME",
		19: "PR_GET_ENDIAN",
		20: "PR_SET_ENDIAN",
		21: "PR_GET_SECCOMP",
		22: "PR_SET_SECCOMP",
		23: "PR_CAPBSET_READ",
		24: "PR_CAPBSET_DROP",
		25: "PR_GET_TSC",
		26: "PR_SET_TSC",
		27: "PR_GET_SECUREBITS",
		28: "PR_SET_SECUREBITS",
		29: "PR_SET_TIMERSLACK",
		30: "PR_GET_TIMERSLACK",
		31: "PR_TASK_PERF_EVENTS_DISABLE",
		32: "PR_TASK_PERF_EVENTS_ENABLE",
		33: "PR_MCE_KILL",
		34: "PR_MCE_KILL_GET",
		35: "PR_SET_MM",
		36: "PR_SET_CHILD_SUBREAPER",
		37: "PR_GET_CHILD_SUBREAPER",
		38: "PR_SET_NO_NEW_PRIVS",
		39: "PR_GET_NO_NEW_PRIVS",
		40: "PR_GET_TID_ADDRESS",
		41: "PR_SET_THP_DISABLE",
		42: "PR_GET_THP_DISABLE",
		43: "PR_MPX_ENABLE_MANAGEMENT",
		44: "PR_MPX_DISABLE_MANAGEMENT",
		45: "PR_SET_FP_MODE",
		46: "PR_GET_FP_MODE",
		47: "PR_CAP_AMBIENT",
		50: "PR_SVE_SET_VL",
		51: "PR_SVE_GET_VL",
		52: "PR_GET_SPECULATION_CTRL",
		53: "PR_SET_SPECULATION_CTRL",
		54: "PR_PAC_RESET_KEYS",
		55: "PR_SET_TAGGED_ADDR_CTRL",
		56: "PR_GET_TAGGED_ADDR_CTRL",
	}

	var res string
	if opName, ok := prctlOptions[p]; ok {
		res = opName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

type BPFCommandArgument uint64

func (b BPFCommandArgument) Value() uint64 { return uint64(b) }

// String parses the `cmd` argument of the `bpf` syscall
// https://man7.org/linux/man-pages/man2/bpf.2.html
func (b BPFCommandArgument) String() string {
	var bpfCmd = map[BPFCommandArgument]string{
		0:  "BPF_MAP_CREATE",
		1:  "BPF_MAP_LOOKUP_ELEM",
		2:  "BPF_MAP_UPDATE_ELEM",
		3:  "BPF_MAP_DELETE_ELEM",
		4:  "BPF_MAP_GET_NEXT_KEY",
		5:  "BPF_PROG_LOAD",
		6:  "BPF_OBJ_PIN",
		7:  "BPF_OBJ_GET",
		8:  "BPF_PROG_ATTACH",
		9:  "BPF_PROG_DETACH",
		10: "BPF_PROG_TEST_RUN",
		11: "BPF_PROG_GET_NEXT_ID",
		12: "BPF_MAP_GET_NEXT_ID",
		13: "BPF_PROG_GET_FD_BY_ID",
		14: "BPF_MAP_GET_FD_BY_ID",
		15: "BPF_OBJ_GET_INFO_BY_FD",
		16: "BPF_PROG_QUERY",
		17: "BPF_RAW_TRACEPOINT_OPEN",
		18: "BPF_BTF_LOAD",
		19: "BPF_BTF_GET_FD_BY_ID",
		20: "BPF_TASK_FD_QUERY",
		21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
		22: "BPF_MAP_FREEZE",
		23: "BPF_BTF_GET_NEXT_ID",
		24: "BPF_MAP_LOOKUP_BATCH",
		25: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
		26: "BPF_MAP_UPDATE_BATCH",
		27: "BPF_MAP_DELETE_BATCH",
		28: "BPF_LINK_CREATE",
		29: "BPF_LINK_UPDATE",
		30: "BPF_LINK_GET_FD_BY_ID",
		31: "BPF_LINK_GET_NEXT_ID",
		32: "BPF_ENABLE_STATS",
		33: "BPF_ITER_CREATE",
		34: "BPF_LINK_DETACH",
	}

	var res string
	if cmdName, ok := bpfCmd[b]; ok {
		res = cmdName
	} else {
		res = strconv.Itoa(int(b))
	}

	return res
}

type PtraceRequestArgument uint64

func (p PtraceRequestArgument) Value() uint64 { return uint64(p) }

func (p PtraceRequestArgument) String() string {
	var ptraceRequest = map[PtraceRequestArgument]string{
		0:      "PTRACE_TRACEME",
		1:      "PTRACE_PEEKTEXT",
		2:      "PTRACE_PEEKDATA",
		3:      "PTRACE_PEEKUSER",
		4:      "PTRACE_POKETEXT",
		5:      "PTRACE_POKEDATA",
		6:      "PTRACE_POKEUSER",
		7:      "PTRACE_CONT",
		8:      "PTRACE_KILL",
		9:      "PTRACE_SINGLESTEP",
		12:     "PTRACE_GETREGS",
		13:     "PTRACE_SETREGS",
		14:     "PTRACE_GETFPREGS",
		15:     "PTRACE_SETFPREGS",
		16:     "PTRACE_ATTACH",
		17:     "PTRACE_DETACH",
		18:     "PTRACE_GETFPXREGS",
		19:     "PTRACE_SETFPXREGS",
		24:     "PTRACE_SYSCALL",
		0x4200: "PTRACE_SETOPTIONS",
		0x4201: "PTRACE_GETEVENTMSG",
		0x4202: "PTRACE_GETSIGINFO",
		0x4203: "PTRACE_SETSIGINFO",
		0x4204: "PTRACE_GETREGSET",
		0x4205: "PTRACE_SETREGSET",
		0x4206: "PTRACE_SEIZE",
		0x4207: "PTRACE_INTERRUPT",
		0x4208: "PTRACE_LISTEN",
		0x4209: "PTRACE_PEEKSIGINFO",
		0x420a: "PTRACE_GETSIGMASK",
		0x420b: "PTRACE_SETSIGMASK",
		0x420c: "PTRACE_SECCOMP_GET_FILTER",
		0x420d: "PTRACE_SECCOMP_GET_METADATA",
	}

	var res string
	if reqName, ok := ptraceRequest[p]; ok {
		res = reqName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

type SocketDomainArgument uint64

func (s SocketDomainArgument) Value() uint64 { return uint64(s) }

// String parses the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func (s SocketDomainArgument) String() string {
	var socketDomains = map[SocketDomainArgument]string{
		0:  "AF_UNSPEC",
		1:  "AF_UNIX",
		2:  "AF_INET",
		3:  "AF_AX25",
		4:  "AF_IPX",
		5:  "AF_APPLETALK",
		6:  "AF_NETROM",
		7:  "AF_BRIDGE",
		8:  "AF_ATMPVC",
		9:  "AF_X25",
		10: "AF_INET6",
		11: "AF_ROSE",
		12: "AF_DECnet",
		13: "AF_NETBEUI",
		14: "AF_SECURITY",
		15: "AF_KEY",
		16: "AF_NETLINK",
		17: "AF_PACKET",
		18: "AF_ASH",
		19: "AF_ECONET",
		20: "AF_ATMSVC",
		21: "AF_RDS",
		22: "AF_SNA",
		23: "AF_IRDA",
		24: "AF_PPPOX",
		25: "AF_WANPIPE",
		26: "AF_LLC",
		27: "AF_IB",
		28: "AF_MPLS",
		29: "AF_CAN",
		30: "AF_TIPC",
		31: "AF_BLUETOOTH",
		32: "AF_IUCV",
		33: "AF_RXRPC",
		34: "AF_ISDN",
		35: "AF_PHONET",
		36: "AF_IEEE802154",
		37: "AF_CAIF",
		38: "AF_ALG",
		39: "AF_NFC",
		40: "AF_VSOCK",
		41: "AF_KCM",
		42: "AF_QIPCRTR",
		43: "AF_SMC",
		44: "AF_XDP",
	}

	var res string

	if sdName, ok := socketDomains[s]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(s))
	}

	return res
}

type SocketTypeArgument uint64

func (s SocketTypeArgument) Value() uint64 { return uint64(s) }

// String parses the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func (s SocketTypeArgument) String() string {
	var socketTypes = map[SocketTypeArgument]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}

	var f []string

	if stName, ok := socketTypes[s&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(s)))
	}
	if OptionAreContainedInArgument(s, SOCK_NONBLOCK) {
		f = append(f, "SOCK_NONBLOCK")
	}
	if OptionAreContainedInArgument(s, SOCK_CLOEXEC) {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

type InodeModeArgument uint64

func (mode InodeModeArgument) Value() uint64 { return uint64(mode) }

func (mode InodeModeArgument) String() string {
	var f []string

	// File Type
	switch {
	case OptionAreContainedInArgument(mode, S_IFSOCK):
		f = append(f, "S_IFSOCK")
	case OptionAreContainedInArgument(mode, S_IFLNK):
		f = append(f, "S_IFLNK")
	case OptionAreContainedInArgument(mode, S_IFREG):
		f = append(f, "S_IFREG")
	case OptionAreContainedInArgument(mode, S_IFBLK):
		f = append(f, "S_IFBLK")
	case OptionAreContainedInArgument(mode, S_IFDIR):
		f = append(f, "S_IFDIR")
	case OptionAreContainedInArgument(mode, S_IFCHR):
		f = append(f, "S_IFCHR")
	case OptionAreContainedInArgument(mode, S_IFIFO):
		f = append(f, "S_IFIFO")
	}

	// File Mode
	// Owner
	if OptionAreContainedInArgument(mode, S_IRWXU) {
		f = append(f, "S_IRWXU")
	} else {
		if OptionAreContainedInArgument(mode, S_IRUSR) {
			f = append(f, "S_IRUSR")
		}
		if OptionAreContainedInArgument(mode, S_IWUSR) {
			f = append(f, "S_IWUSR")
		}
		if OptionAreContainedInArgument(mode, S_IXUSR) {
			f = append(f, "S_IXUSR")
		}
	}
	// Group
	if OptionAreContainedInArgument(mode, S_IRWXG) {
		f = append(f, "S_IRWXG")
	} else {
		if OptionAreContainedInArgument(mode, S_IRGRP) {
			f = append(f, "S_IRGRP")
		}
		if OptionAreContainedInArgument(mode, S_IWGRP) {
			f = append(f, "S_IWGRP")
		}
		if OptionAreContainedInArgument(mode, S_IXGRP) {
			f = append(f, "S_IXGRP")
		}
	}
	// Others
	if OptionAreContainedInArgument(mode, S_IRWXO) {
		f = append(f, "S_IRWXO")
	} else {
		if OptionAreContainedInArgument(mode, S_IROTH) {
			f = append(f, "S_IROTH")
		}
		if OptionAreContainedInArgument(mode, S_IWOTH) {
			f = append(f, "S_IWOTH")
		}
		if OptionAreContainedInArgument(mode, S_IXOTH) {
			f = append(f, "S_IXOTH")
		}
	}

	return strings.Join(f, "|")
}

type MmapProtArgument uint64

func (p MmapProtArgument) Value() uint64 { return uint64(p) }

// String parses the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func (p MmapProtArgument) String() string {
	var f []string
	if p == PROT_NONE {
		f = append(f, "PROT_NONE")
	} else {
		if OptionAreContainedInArgument(p, PROT_READ) {
			f = append(f, "PROT_READ")
		}
		if OptionAreContainedInArgument(p, PROT_WRITE) {
			f = append(f, "PROT_WRITE")
		}
		if OptionAreContainedInArgument(p, PROT_EXEC) {
			f = append(f, "PROT_EXEC")
		}
		if OptionAreContainedInArgument(p, PROT_SEM) {
			f = append(f, "PROT_SEM")
		}
		if OptionAreContainedInArgument(p, PROT_GROWSDOWN) {
			f = append(f, "PROT_GROWSDOWN")
		}
		if OptionAreContainedInArgument(p, PROT_GROWSUP) {
			f = append(f, "PROT_GROWSUP")
		}
	}

	return strings.Join(f, "|")
}

// ParseUint32IP parses the IP address encoded as a uint32
func ParseUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)

	return ip.String()
}

// Parse16BytesSliceIP parses the IP address encoded as 16 bytes long
// PrintBytesSliceIP. It would be more correct to accept a [16]byte instead of
// variable lenth slice, but that would case unnecessary memory copying and
// type conversions.
func Parse16BytesSliceIP(in []byte) string {
	ip := net.IP(in)

	return ip.String()
}

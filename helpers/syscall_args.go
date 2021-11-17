package helpers

import (
	"fmt"
	"strconv"
	"strings"
)

type SystemCallArgument interface {
	fmt.Stringer
	Value() uint64
}

const (
	// These values are copied from uapi/linux/sched.h
	CLONE_VM             CloneFlagArgument = 0x00000100 /* set if VM shared between processes */
	CLONE_FS             CloneFlagArgument = 0x00000200 /* set if fs info shared between processes */
	CLONE_FILES          CloneFlagArgument = 0x00000400 /* set if open files shared between processes */
	CLONE_SIGHAND        CloneFlagArgument = 0x00000800 /* set if signal handlers and blocked signals shared */
	CLONE_PIDFD          CloneFlagArgument = 0x00001000 /* set if a pidfd should be placed in parent */
	CLONE_PTRACE         CloneFlagArgument = 0x00002000 /* set if we want to let tracing continue on the child too */
	CLONE_VFORK          CloneFlagArgument = 0x00004000 /* set if the parent wants the child to wake it up on mm_release */
	CLONE_PARENT         CloneFlagArgument = 0x00008000 /* set if we want to have the same parent as the cloner */
	CLONE_THREAD         CloneFlagArgument = 0x00010000 /* Same thread group? */
	CLONE_NEWNS          CloneFlagArgument = 0x00020000 /* New mount namespace group */
	CLONE_SYSVSEM        CloneFlagArgument = 0x00040000 /* share system V SEM_UNDO semantics */
	CLONE_SETTLS         CloneFlagArgument = 0x00080000 /* create a new TLS for the child */
	CLONE_PARENT_SETTID  CloneFlagArgument = 0x00100000 /* set the TID in the parent */
	CLONE_CHILD_CLEARTID CloneFlagArgument = 0x00200000 /* clear the TID in the child */
	CLONE_DETACHED       CloneFlagArgument = 0x00400000 /* Unused ignored */
	CLONE_UNTRACED       CloneFlagArgument = 0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this clone */
	CLONE_CHILD_SETTID   CloneFlagArgument = 0x01000000 /* set the TID in the child */
	CLONE_NEWCGROUP      CloneFlagArgument = 0x02000000 /* New cgroup namespace */
	CLONE_NEWUTS         CloneFlagArgument = 0x04000000 /* New utsname namespace */
	CLONE_NEWIPC         CloneFlagArgument = 0x08000000 /* New ipc namespace */
	CLONE_NEWUSER        CloneFlagArgument = 0x10000000 /* New user namespace */
	CLONE_NEWPID         CloneFlagArgument = 0x20000000 /* New pid namespace */
	CLONE_NEWNET         CloneFlagArgument = 0x40000000 /* New network namespace */
	CLONE_IO             CloneFlagArgument = 0x80000000 /* Clone io context */

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

// OptionIsContainedInArgument checks whether the argument (rawArgument)
// contains the 'option' such as with flags passed to the clone flag.
// Typically linux syscalls have multiple options specified in a single
// argument via bitmasks, which this function checks for.
func OptionIsContainedInArgument(rawArgument SystemCallArgument, option SystemCallArgument) bool {
	return option.Value()&rawArgument.Value() == option.Value()
}

type CloneFlagArgument uint64

func (c CloneFlagArgument) Value() uint64 { return uint64(c) }

func (c CloneFlagArgument) String() string {
	var f []string
	if OptionIsContainedInArgument(c, CLONE_VM) {
		f = append(f, "CLONE_VM")
	}
	if OptionIsContainedInArgument(c, CLONE_FS) {
		f = append(f, "CLONE_FS")
	}
	if OptionIsContainedInArgument(c, CLONE_FILES) {
		f = append(f, "CLONE_FILES")
	}
	if OptionIsContainedInArgument(c, CLONE_SIGHAND) {
		f = append(f, "CLONE_SIGHAND")
	}
	if OptionIsContainedInArgument(c, CLONE_PIDFD) {
		f = append(f, "CLONE_PIDFD")
	}
	if OptionIsContainedInArgument(c, CLONE_PTRACE) {
		f = append(f, "CLONE_PTRACE")
	}
	if OptionIsContainedInArgument(c, CLONE_VFORK) {
		f = append(f, "CLONE_VFORK")
	}
	if OptionIsContainedInArgument(c, CLONE_PARENT) {
		f = append(f, "CLONE_PARENT")
	}
	if OptionIsContainedInArgument(c, CLONE_THREAD) {
		f = append(f, "CLONE_THREAD")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWNS) {
		f = append(f, "CLONE_NEWNS")
	}
	if OptionIsContainedInArgument(c, CLONE_SYSVSEM) {
		f = append(f, "CLONE_SYSVSEM")
	}
	if OptionIsContainedInArgument(c, CLONE_SETTLS) {
		f = append(f, "CLONE_SETTLS")
	}
	if OptionIsContainedInArgument(c, CLONE_PARENT_SETTID) {
		f = append(f, "CLONE_PARENT_SETTID")
	}
	if OptionIsContainedInArgument(c, CLONE_CHILD_CLEARTID) {
		f = append(f, "CLONE_CHILD_CLEARTID")
	}
	if OptionIsContainedInArgument(c, CLONE_DETACHED) {
		f = append(f, "CLONE_DETACHED")
	}
	if OptionIsContainedInArgument(c, CLONE_UNTRACED) {
		f = append(f, "CLONE_UNTRACED")
	}
	if OptionIsContainedInArgument(c, CLONE_CHILD_SETTID) {
		f = append(f, "CLONE_CHILD_SETTID")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWCGROUP) {
		f = append(f, "CLONE_NEWCGROUP")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWUTS) {
		f = append(f, "CLONE_NEWUTS")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWIPC) {
		f = append(f, "CLONE_NEWIPC")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWUSER) {
		f = append(f, "CLONE_NEWUSER")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWPID) {
		f = append(f, "CLONE_NEWPID")
	}
	if OptionIsContainedInArgument(c, CLONE_NEWNET) {
		f = append(f, "CLONE_NEWNET")
	}
	if OptionIsContainedInArgument(c, CLONE_IO) {
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
	case OptionIsContainedInArgument(o, O_WRONLY):
		f = append(f, "O_WRONLY")
	case OptionIsContainedInArgument(o, O_RDWR):
		f = append(f, "O_RDWR")
	default:
		f = append(f, "O_RDONLY")
	}

	// file creation and status flags
	if OptionIsContainedInArgument(o, O_CREAT) {
		f = append(f, "O_CREAT")
	}
	if OptionIsContainedInArgument(o, O_EXCL) {
		f = append(f, "O_EXCL")
	}
	if OptionIsContainedInArgument(o, O_NOCTTY) {
		f = append(f, "O_NOCTTY")
	}
	if OptionIsContainedInArgument(o, O_TRUNC) {
		f = append(f, "O_TRUNC")
	}
	if OptionIsContainedInArgument(o, O_APPEND) {
		f = append(f, "O_APPEND")
	}
	if OptionIsContainedInArgument(o, O_NONBLOCK) {
		f = append(f, "O_NONBLOCK")
	}
	if OptionIsContainedInArgument(o, O_SYNC) {
		f = append(f, "O_SYNC")
	}
	if OptionIsContainedInArgument(o, O_ASYNC) {
		f = append(f, "O_ASYNC")
	}
	if OptionIsContainedInArgument(o, O_LARGEFILE) {
		f = append(f, "O_LARGEFILE")
	}
	if OptionIsContainedInArgument(o, O_DIRECTORY) {
		f = append(f, "O_DIRECTORY")
	}
	if OptionIsContainedInArgument(o, O_NOFOLLOW) {
		f = append(f, "O_NOFOLLOW")
	}
	if OptionIsContainedInArgument(o, O_CLOEXEC) {
		f = append(f, "O_CLOEXEC")
	}
	if OptionIsContainedInArgument(o, O_DIRECT) {
		f = append(f, "O_DIRECT")
	}
	if OptionIsContainedInArgument(o, O_NOATIME) {
		f = append(f, "O_NOATIME")
	}
	if OptionIsContainedInArgument(o, O_PATH) {
		f = append(f, "O_PATH")
	}
	if OptionIsContainedInArgument(o, O_TMPFILE) {
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
		if OptionIsContainedInArgument(a, R_OK) {
			f = append(f, "R_OK")
		}
		if OptionIsContainedInArgument(a, W_OK) {
			f = append(f, "W_OK")
		}
		if OptionIsContainedInArgument(a, X_OK) {
			f = append(f, "X_OK")
		}
	}
	return strings.Join(f, "|")
}

type ExecFlagArgument uint64

func (e ExecFlagArgument) Value() uint64 { return uint64(e) }

func (e ExecFlagArgument) String() string {
	var f []string
	if OptionIsContainedInArgument(e, AT_EMPTY_PATH) {
		f = append(f, "AT_EMPTY_PATH")
	}
	if OptionIsContainedInArgument(e, AT_SYMLINK_NOFOLLOW) {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if OptionIsContainedInArgument(e, AT_EACCESS) {
		f = append(f, "AT_EACCESS")
	}
	if OptionIsContainedInArgument(e, AT_REMOVEDIR) {
		f = append(f, "AT_REMOVEDIR")
	}
	if OptionIsContainedInArgument(e, AT_NO_AUTOMOUNT) {
		f = append(f, "AT_NO_AUTOMOUNT")
	}
	if OptionIsContainedInArgument(e, AT_STATX_SYNC_TYPE) {
		f = append(f, "AT_STATX_SYNC_TYPE")
	}
	if OptionIsContainedInArgument(e, AT_STATX_FORCE_SYNC) {
		f = append(f, "AT_STATX_FORCE_SYNC")
	}
	if OptionIsContainedInArgument(e, AT_STATX_DONT_SYNC) {
		f = append(f, "AT_STATX_DONT_SYNC")
	}
	if OptionIsContainedInArgument(e, AT_RECURSIVE) {
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

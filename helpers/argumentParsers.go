package helpers

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type SystemFunctionArgument interface {
	fmt.Stringer
	Value() uint64
}

// OptionAreContainedInArgument checks whether the argument (rawArgument)
// contains all of the 'options' such as with flags passed to the clone flag.
// This function takes an arbitrary number of SystemCallArguments.It will
// only return true if each and every option is present in rawArgument.
// Typically linux syscalls have multiple options specified in a single
// argument via bitmasks = which this function checks for.
func OptionAreContainedInArgument(rawArgument uint64, options ...SystemFunctionArgument) bool {
	var isPresent = true
	for _, option := range options {
		isPresent = isPresent && (option.Value()&rawArgument == option.Value())
	}
	return isPresent
}

type CloneFlagArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	// These values are copied from uapi/linux/sched.h
	CLONE_VM             CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000100, stringValue: "CLONE_VM"}
	CLONE_FS             CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000200, stringValue: "CLONE_FS"}
	CLONE_FILES          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000400, stringValue: "CLONE_FILES"}
	CLONE_SIGHAND        CloneFlagArgument = CloneFlagArgument{rawValue: 0x00000800, stringValue: "CLONE_SIGHAND"}
	CLONE_PIDFD          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00001000, stringValue: "CLONE_PIDFD"}
	CLONE_PTRACE         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00002000, stringValue: "CLONE_PTRACE"}
	CLONE_VFORK          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00004000, stringValue: "CLONE_VFORK"}
	CLONE_PARENT         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00008000, stringValue: "CLONE_PARENT"}
	CLONE_THREAD         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00010000, stringValue: "CLONE_THREAD"}
	CLONE_NEWNS          CloneFlagArgument = CloneFlagArgument{rawValue: 0x00020000, stringValue: "CLONE_NEWNS"}
	CLONE_SYSVSEM        CloneFlagArgument = CloneFlagArgument{rawValue: 0x00040000, stringValue: "CLONE_SYSVSEM"}
	CLONE_SETTLS         CloneFlagArgument = CloneFlagArgument{rawValue: 0x00080000, stringValue: "CLONE_SETTLS"}
	CLONE_PARENT_SETTID  CloneFlagArgument = CloneFlagArgument{rawValue: 0x00100000, stringValue: "CLONE_PARENT_SETTID"}
	CLONE_CHILD_CLEARTID CloneFlagArgument = CloneFlagArgument{rawValue: 0x00200000, stringValue: "CLONE_CHILD_CLEARTID"}
	CLONE_DETACHED       CloneFlagArgument = CloneFlagArgument{rawValue: 0x00400000, stringValue: "CLONE_DETACHED"}
	CLONE_UNTRACED       CloneFlagArgument = CloneFlagArgument{rawValue: 0x00800000, stringValue: "CLONE_UNTRACED"}
	CLONE_CHILD_SETTID   CloneFlagArgument = CloneFlagArgument{rawValue: 0x01000000, stringValue: "CLONE_CHILD_SETTID"}
	CLONE_NEWCGROUP      CloneFlagArgument = CloneFlagArgument{rawValue: 0x02000000, stringValue: "CLONE_NEWCGROUP"}
	CLONE_NEWUTS         CloneFlagArgument = CloneFlagArgument{rawValue: 0x04000000, stringValue: "CLONE_NEWUTS"}
	CLONE_NEWIPC         CloneFlagArgument = CloneFlagArgument{rawValue: 0x08000000, stringValue: "CLONE_NEWIPC"}
	CLONE_NEWUSER        CloneFlagArgument = CloneFlagArgument{rawValue: 0x10000000, stringValue: "CLONE_NEWUSER"}
	CLONE_NEWPID         CloneFlagArgument = CloneFlagArgument{rawValue: 0x20000000, stringValue: "CLONE_NEWPID"}
	CLONE_NEWNET         CloneFlagArgument = CloneFlagArgument{rawValue: 0x40000000, stringValue: "CLONE_NEWNET"}
	CLONE_IO             CloneFlagArgument = CloneFlagArgument{rawValue: 0x80000000, stringValue: "CLONE_IO"}
)

func (c CloneFlagArgument) Value() uint64  { return c.rawValue }
func (c CloneFlagArgument) String() string { return c.stringValue }

func ParseCloneFlags(rawValue uint64) (CloneFlagArgument, error) {

	if rawValue == 0 {
		return CloneFlagArgument{}, nil
	}

	var f []string
	if OptionAreContainedInArgument(rawValue, CLONE_VM) {
		f = append(f, CLONE_VM.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_FS) {
		f = append(f, CLONE_FS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_FILES) {
		f = append(f, CLONE_FILES.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SIGHAND) {
		f = append(f, CLONE_SIGHAND.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PIDFD) {
		f = append(f, CLONE_PIDFD.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PTRACE) {
		f = append(f, CLONE_PTRACE.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_VFORK) {
		f = append(f, CLONE_VFORK.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PARENT) {
		f = append(f, CLONE_PARENT.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_THREAD) {
		f = append(f, CLONE_THREAD.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWNS) {
		f = append(f, CLONE_NEWNS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SYSVSEM) {
		f = append(f, CLONE_SYSVSEM.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_SETTLS) {
		f = append(f, CLONE_SETTLS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_PARENT_SETTID) {
		f = append(f, CLONE_PARENT_SETTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_CHILD_CLEARTID) {
		f = append(f, CLONE_CHILD_CLEARTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_DETACHED) {
		f = append(f, CLONE_DETACHED.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_UNTRACED) {
		f = append(f, CLONE_UNTRACED.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_CHILD_SETTID) {
		f = append(f, CLONE_CHILD_SETTID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWCGROUP) {
		f = append(f, CLONE_NEWCGROUP.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWUTS) {
		f = append(f, CLONE_NEWUTS.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWIPC) {
		f = append(f, CLONE_NEWIPC.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWUSER) {
		f = append(f, CLONE_NEWUSER.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWPID) {
		f = append(f, CLONE_NEWPID.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_NEWNET) {
		f = append(f, CLONE_NEWNET.String())
	}
	if OptionAreContainedInArgument(rawValue, CLONE_IO) {
		f = append(f, CLONE_IO.String())
	}
	if len(f) == 0 {
		return CloneFlagArgument{}, fmt.Errorf("no valid clone flag values present in raw value: 0x%x", rawValue)
	}

	return CloneFlagArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type OpenFlagArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	// These values are copied from uapi/asm-generic/fcntl.h
	O_ACCMODE   OpenFlagArgument = OpenFlagArgument{rawValue: 00000003, stringValue: "O_ACCMODE"}
	O_RDONLY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000000, stringValue: "O_RDONLY"}
	O_WRONLY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000001, stringValue: "O_WRONLY"}
	O_RDWR      OpenFlagArgument = OpenFlagArgument{rawValue: 00000002, stringValue: "O_RDWR"}
	O_CREAT     OpenFlagArgument = OpenFlagArgument{rawValue: 00000100, stringValue: "O_CREAT"}
	O_EXCL      OpenFlagArgument = OpenFlagArgument{rawValue: 00000200, stringValue: "O_EXCL"}
	O_NOCTTY    OpenFlagArgument = OpenFlagArgument{rawValue: 00000400, stringValue: "O_NOCTTY"}
	O_TRUNC     OpenFlagArgument = OpenFlagArgument{rawValue: 00001000, stringValue: "O_TRUNC"}
	O_APPEND    OpenFlagArgument = OpenFlagArgument{rawValue: 00002000, stringValue: "O_APPEND"}
	O_NONBLOCK  OpenFlagArgument = OpenFlagArgument{rawValue: 00004000, stringValue: "O_NONBLOCK"}
	O_DSYNC     OpenFlagArgument = OpenFlagArgument{rawValue: 00010000, stringValue: "O_DSYNC"}
	O_SYNC      OpenFlagArgument = OpenFlagArgument{rawValue: 04010000, stringValue: "O_SYNC"}
	FASYNC      OpenFlagArgument = OpenFlagArgument{rawValue: 00020000, stringValue: "FASYNC"}
	O_DIRECT    OpenFlagArgument = OpenFlagArgument{rawValue: 00040000, stringValue: "O_DIRECT"}
	O_LARGEFILE OpenFlagArgument = OpenFlagArgument{rawValue: 00100000, stringValue: "O_LARGEFILE"}
	O_DIRECTORY OpenFlagArgument = OpenFlagArgument{rawValue: 00200000, stringValue: "O_DIRECTORY"}
	O_NOFOLLOW  OpenFlagArgument = OpenFlagArgument{rawValue: 00400000, stringValue: "O_NOFOLLOW"}
	O_NOATIME   OpenFlagArgument = OpenFlagArgument{rawValue: 01000000, stringValue: "O_NOATIME"}
	O_CLOEXEC   OpenFlagArgument = OpenFlagArgument{rawValue: 02000000, stringValue: "O_CLOEXEC"}
	O_PATH      OpenFlagArgument = OpenFlagArgument{rawValue: 040000000, stringValue: "O_PATH"}
	O_TMPFILE   OpenFlagArgument = OpenFlagArgument{rawValue: 020000000, stringValue: "O_TMPFILE"}
)

func (o OpenFlagArgument) Value() uint64  { return o.rawValue }
func (o OpenFlagArgument) String() string { return o.stringValue }

// ParseOpenFlagArgument parses the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func ParseOpenFlagArgument(rawValue uint64) (OpenFlagArgument, error) {
	if rawValue == 0 {
		return OpenFlagArgument{}, nil
	}
	var f []string

	// access mode
	switch {
	case OptionAreContainedInArgument(rawValue, O_WRONLY):
		f = append(f, O_WRONLY.String())
	case OptionAreContainedInArgument(rawValue, O_RDWR):
		f = append(f, O_RDWR.String())
	default:
		f = append(f, O_RDONLY.String())
	}

	// file creation and status flags
	if OptionAreContainedInArgument(rawValue, O_CREAT) {
		f = append(f, O_CREAT.String())
	}
	if OptionAreContainedInArgument(rawValue, O_EXCL) {
		f = append(f, O_EXCL.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOCTTY) {
		f = append(f, O_NOCTTY.String())
	}
	if OptionAreContainedInArgument(rawValue, O_TRUNC) {
		f = append(f, O_TRUNC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_APPEND) {
		f = append(f, O_APPEND.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NONBLOCK) {
		f = append(f, O_NONBLOCK.String())
	}
	if OptionAreContainedInArgument(rawValue, O_SYNC) {
		f = append(f, O_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, FASYNC) {
		f = append(f, FASYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_LARGEFILE) {
		f = append(f, O_LARGEFILE.String())
	}
	if OptionAreContainedInArgument(rawValue, O_DIRECTORY) {
		f = append(f, O_DIRECTORY.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOFOLLOW) {
		f = append(f, O_NOFOLLOW.String())
	}
	if OptionAreContainedInArgument(rawValue, O_CLOEXEC) {
		f = append(f, O_CLOEXEC.String())
	}
	if OptionAreContainedInArgument(rawValue, O_DIRECT) {
		f = append(f, O_DIRECT.String())
	}
	if OptionAreContainedInArgument(rawValue, O_NOATIME) {
		f = append(f, O_NOATIME.String())
	}
	if OptionAreContainedInArgument(rawValue, O_PATH) {
		f = append(f, O_PATH.String())
	}
	if OptionAreContainedInArgument(rawValue, O_TMPFILE) {
		f = append(f, O_TMPFILE.String())
	}

	if len(f) == 0 {
		return OpenFlagArgument{}, fmt.Errorf("no valid open flag values present in raw value: 0x%x", rawValue)
	}

	return OpenFlagArgument{rawValue: rawValue, stringValue: strings.Join(f, "|")}, nil
}

type AccessModeArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	F_OK AccessModeArgument = AccessModeArgument{rawValue: 0, stringValue: "F_OK"}
	X_OK AccessModeArgument = AccessModeArgument{rawValue: 1, stringValue: "X_OK"}
	W_OK AccessModeArgument = AccessModeArgument{rawValue: 2, stringValue: "W_OK"}
	R_OK AccessModeArgument = AccessModeArgument{rawValue: 4, stringValue: "R_OK"}
)

func (a AccessModeArgument) Value() uint64 { return a.rawValue }

func (a AccessModeArgument) String() string { return a.stringValue }

// ParseAccessMode parses the mode from the `access` system call
// http://man7.org/linux/man-pages/man2/access.2.html
func ParseAccessMode(rawValue uint64) (AccessModeArgument, error) {
	if rawValue == 0 {
		return AccessModeArgument{}, nil
	}
	var f []string
	if rawValue == 0x0 {
		f = append(f, F_OK.String())
	} else {
		if OptionAreContainedInArgument(rawValue, R_OK) {
			f = append(f, R_OK.String())
		}
		if OptionAreContainedInArgument(rawValue, W_OK) {
			f = append(f, W_OK.String())
		}
		if OptionAreContainedInArgument(rawValue, X_OK) {
			f = append(f, X_OK.String())
		}
	}

	if len(f) == 0 {
		return AccessModeArgument{}, fmt.Errorf("no valid access mode values present in raw value: 0x%x", rawValue)
	}

	return AccessModeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type ExecFlagArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	AT_SYMLINK_NOFOLLOW   ExecFlagArgument = ExecFlagArgument{stringValue: "AT_SYMLINK_NOFOLLOW", rawValue: 0x100}
	AT_EACCESS            ExecFlagArgument = ExecFlagArgument{stringValue: "AT_EACCESS", rawValue: 0x200}
	AT_REMOVEDIR          ExecFlagArgument = ExecFlagArgument{stringValue: "AT_REMOVEDIR", rawValue: 0x200}
	AT_SYMLINK_FOLLOW     ExecFlagArgument = ExecFlagArgument{stringValue: "AT_SYMLINK_FOLLOW", rawValue: 0x400}
	AT_NO_AUTOMOUNT       ExecFlagArgument = ExecFlagArgument{stringValue: "AT_NO_AUTOMOUNT", rawValue: 0x800}
	AT_EMPTY_PATH         ExecFlagArgument = ExecFlagArgument{stringValue: "AT_EMPTY_PATH", rawValue: 0x1000}
	AT_STATX_SYNC_TYPE    ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_SYNC_TYPE", rawValue: 0x6000}
	AT_STATX_SYNC_AS_STAT ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_SYNC_AS_STAT", rawValue: 0x0000}
	AT_STATX_FORCE_SYNC   ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_FORCE_SYNC", rawValue: 0x2000}
	AT_STATX_DONT_SYNC    ExecFlagArgument = ExecFlagArgument{stringValue: "AT_STATX_DONT_SYNC", rawValue: 0x4000}
	AT_RECURSIVE          ExecFlagArgument = ExecFlagArgument{stringValue: "AT_RECURSIVE", rawValue: 0x8000}
)

func (e ExecFlagArgument) Value() uint64  { return e.rawValue }
func (e ExecFlagArgument) String() string { return e.stringValue }

func ParseExecFlag(rawValue uint64) (ExecFlagArgument, error) {

	if rawValue == 0 {
		return ExecFlagArgument{}, nil
	}

	var f []string
	if OptionAreContainedInArgument(rawValue, AT_EMPTY_PATH) {
		f = append(f, AT_EMPTY_PATH.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_SYMLINK_NOFOLLOW) {
		f = append(f, AT_SYMLINK_NOFOLLOW.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_EACCESS) {
		f = append(f, AT_EACCESS.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_REMOVEDIR) {
		f = append(f, AT_REMOVEDIR.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_NO_AUTOMOUNT) {
		f = append(f, AT_NO_AUTOMOUNT.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_SYNC_TYPE) {
		f = append(f, AT_STATX_SYNC_TYPE.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_FORCE_SYNC) {
		f = append(f, AT_STATX_FORCE_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_STATX_DONT_SYNC) {
		f = append(f, AT_STATX_DONT_SYNC.String())
	}
	if OptionAreContainedInArgument(rawValue, AT_RECURSIVE) {
		f = append(f, AT_RECURSIVE.String())
	}
	if len(f) == 0 {
		return ExecFlagArgument{}, fmt.Errorf("no valid exec flag values present in raw value: 0x%x", rawValue)
	}
	return ExecFlagArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type CapabilityFlagArgument uint64

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

func (c CapabilityFlagArgument) Value() uint64 { return uint64(c) }

var capFlagStringMap = map[CapabilityFlagArgument]string{
	CAP_CHOWN:            "CAP_CHOWN",
	CAP_DAC_OVERRIDE:     "CAP_DAC_OVERRIDE",
	CAP_DAC_READ_SEARCH:  "CAP_DAC_READ_SEARCH",
	CAP_FOWNER:           "CAP_FOWNER",
	CAP_FSETID:           "CAP_FSETID",
	CAP_KILL:             "CAP_KILL",
	CAP_SETGID:           "CAP_SETGID",
	CAP_SETUID:           "CAP_SETUID",
	CAP_SETPCAP:          "CAP_SETPCAP",
	CAP_LINUX_IMMUTABLE:  "CAP_LINUX_IMMUTABLE",
	CAP_NET_BIND_SERVICE: "CAP_NET_BIND_SERVICE",
	CAP_NET_BROADCAST:    "CAP_NET_BROADCAST",
	CAP_NET_ADMIN:        "CAP_NET_ADMIN",
	CAP_NET_RAW:          "CAP_NET_RAW",
	CAP_IPC_LOCK:         "CAP_IPC_LOCK",
	CAP_IPC_OWNER:        "CAP_IPC_OWNER",
	CAP_SYS_MODULE:       "CAP_SYS_MODULE",
	CAP_SYS_RAWIO:        "CAP_SYS_RAWIO",
	CAP_SYS_CHROOT:       "CAP_SYS_CHROOT",
	CAP_SYS_PTRACE:       "CAP_SYS_PTRACE",
	CAP_SYS_PACCT:        "CAP_SYS_PACCT",
	CAP_SYS_ADMIN:        "CAP_SYS_ADMIN",
	CAP_SYS_BOOT:         "CAP_SYS_BOOT",
	CAP_SYS_NICE:         "CAP_SYS_NICE",
	CAP_SYS_RESOURCE:     "CAP_SYS_RESOURCE",
	CAP_SYS_TIME:         "CAP_SYS_TIME",
	CAP_SYS_TTY_CONFIG:   "CAP_SYS_TTY_CONFIG",
	CAP_MKNOD:            "CAP_MKNOD",
	CAP_LEASE:            "CAP_LEASE",
	CAP_AUDIT_WRITE:      "CAP_AUDIT_WRITE",
	CAP_AUDIT_CONTROL:    "CAP_AUDIT_CONTROL",
	CAP_SETFCAP:          "CAP_SETFCAP",
	CAP_MAC_OVERRIDE:     "CAP_MAC_OVERRIDE",
	CAP_MAC_ADMIN:        "CAP_MAC_ADMIN",
	CAP_SYSLOG:           "CAP_SYSLOG",
	CAP_WAKE_ALARM:       "CAP_WAKE_ALARM",
	CAP_BLOCK_SUSPEND:    "CAP_BLOCK_SUSPEND",
	CAP_AUDIT_READ:       "CAP_AUDIT_READ",
}

func (c CapabilityFlagArgument) String() string {
	var res string

	if capName, ok := capFlagStringMap[c]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(c))
	}
	return res
}

var capabilitiesMap = map[uint64]CapabilityFlagArgument{
	CAP_CHOWN.Value():            CAP_CHOWN,
	CAP_DAC_OVERRIDE.Value():     CAP_DAC_OVERRIDE,
	CAP_DAC_READ_SEARCH.Value():  CAP_DAC_READ_SEARCH,
	CAP_FOWNER.Value():           CAP_FOWNER,
	CAP_FSETID.Value():           CAP_FSETID,
	CAP_KILL.Value():             CAP_KILL,
	CAP_SETGID.Value():           CAP_SETGID,
	CAP_SETUID.Value():           CAP_SETUID,
	CAP_SETPCAP.Value():          CAP_SETPCAP,
	CAP_LINUX_IMMUTABLE.Value():  CAP_LINUX_IMMUTABLE,
	CAP_NET_BIND_SERVICE.Value(): CAP_NET_BIND_SERVICE,
	CAP_NET_BROADCAST.Value():    CAP_NET_BROADCAST,
	CAP_NET_ADMIN.Value():        CAP_NET_ADMIN,
	CAP_NET_RAW.Value():          CAP_NET_RAW,
	CAP_IPC_LOCK.Value():         CAP_IPC_LOCK,
	CAP_IPC_OWNER.Value():        CAP_IPC_OWNER,
	CAP_SYS_MODULE.Value():       CAP_SYS_MODULE,
	CAP_SYS_RAWIO.Value():        CAP_SYS_RAWIO,
	CAP_SYS_CHROOT.Value():       CAP_SYS_CHROOT,
	CAP_SYS_PTRACE.Value():       CAP_SYS_PTRACE,
	CAP_SYS_PACCT.Value():        CAP_SYS_PACCT,
	CAP_SYS_ADMIN.Value():        CAP_SYS_ADMIN,
	CAP_SYS_BOOT.Value():         CAP_SYS_BOOT,
	CAP_SYS_NICE.Value():         CAP_SYS_NICE,
	CAP_SYS_RESOURCE.Value():     CAP_SYS_RESOURCE,
	CAP_SYS_TIME.Value():         CAP_SYS_TIME,
	CAP_SYS_TTY_CONFIG.Value():   CAP_SYS_TTY_CONFIG,
	CAP_MKNOD.Value():            CAP_MKNOD,
	CAP_LEASE.Value():            CAP_LEASE,
	CAP_AUDIT_WRITE.Value():      CAP_AUDIT_WRITE,
	CAP_AUDIT_CONTROL.Value():    CAP_AUDIT_CONTROL,
	CAP_SETFCAP.Value():          CAP_SETFCAP,
	CAP_MAC_OVERRIDE.Value():     CAP_MAC_OVERRIDE,
	CAP_MAC_ADMIN.Value():        CAP_MAC_ADMIN,
	CAP_SYSLOG.Value():           CAP_SYSLOG,
	CAP_WAKE_ALARM.Value():       CAP_WAKE_ALARM,
	CAP_BLOCK_SUSPEND.Value():    CAP_BLOCK_SUSPEND,
	CAP_AUDIT_READ.Value():       CAP_AUDIT_READ,
}

// ParseCapability parses the `capability` bitmask argument of the
// `cap_capable` function
func ParseCapability(rawValue uint64) (CapabilityFlagArgument, error) {
	v, ok := capabilitiesMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid capability value: %d", rawValue)
	}
	return v, nil
}

type PrctlOptionArgument uint64

const (
	PR_SET_PDEATHSIG PrctlOptionArgument = iota + 1
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

func (p PrctlOptionArgument) Value() uint64 { return uint64(p) }

var prctlOptionStringMap = map[PrctlOptionArgument]string{
	PR_SET_PDEATHSIG:            "PR_SET_PDEATHSIG",
	PR_GET_PDEATHSIG:            "PR_GET_PDEATHSIG",
	PR_GET_DUMPABLE:             "PR_GET_DUMPABLE",
	PR_SET_DUMPABLE:             "PR_SET_DUMPABLE",
	PR_GET_UNALIGN:              "PR_GET_UNALIGN",
	PR_SET_UNALIGN:              "PR_SET_UNALIGN",
	PR_GET_KEEPCAPS:             "PR_GET_KEEPCAPS",
	PR_SET_KEEPCAPS:             "PR_SET_KEEPCAPS",
	PR_GET_FPEMU:                "PR_GET_FPEMU",
	PR_SET_FPEMU:                "PR_SET_FPEMU",
	PR_GET_FPEXC:                "PR_GET_FPEXC",
	PR_SET_FPEXC:                "PR_SET_FPEXC",
	PR_GET_TIMING:               "PR_GET_TIMING",
	PR_SET_TIMING:               "PR_SET_TIMING",
	PR_SET_NAME:                 "PR_SET_NAME",
	PR_GET_NAME:                 "PR_GET_NAME",
	PR_GET_ENDIAN:               "PR_GET_ENDIAN",
	PR_SET_ENDIAN:               "PR_SET_ENDIAN",
	PR_GET_SECCOMP:              "PR_GET_SECCOMP",
	PR_SET_SECCOMP:              "PR_SET_SECCOMP",
	PR_CAPBSET_READ:             "PR_CAPBSET_READ",
	PR_CAPBSET_DROP:             "PR_CAPBSET_DROP",
	PR_GET_TSC:                  "PR_GET_TSC",
	PR_SET_TSC:                  "PR_SET_TSC",
	PR_GET_SECUREBITS:           "PR_GET_SECUREBITS",
	PR_SET_SECUREBITS:           "PR_SET_SECUREBITS",
	PR_SET_TIMERSLACK:           "PR_SET_TIMERSLACK",
	PR_GET_TIMERSLACK:           "PR_GET_TIMERSLACK",
	PR_TASK_PERF_EVENTS_DISABLE: "PR_TASK_PERF_EVENTS_DISABLE",
	PR_TASK_PERF_EVENTS_ENABLE:  "PR_TASK_PERF_EVENTS_ENABLE",
	PR_MCE_KILL:                 "PR_MCE_KILL",
	PR_MCE_KILL_GET:             "PR_MCE_KILL_GET",
	PR_SET_MM:                   "PR_SET_MM",
	PR_SET_CHILD_SUBREAPER:      "PR_SET_CHILD_SUBREAPER",
	PR_GET_CHILD_SUBREAPER:      "PR_GET_CHILD_SUBREAPER",
	PR_SET_NO_NEW_PRIVS:         "PR_SET_NO_NEW_PRIVS",
	PR_GET_NO_NEW_PRIVS:         "PR_GET_NO_NEW_PRIVS",
	PR_GET_TID_ADDRESS:          "PR_GET_TID_ADDRESS",
	PR_SET_THP_DISABLE:          "PR_SET_THP_DISABLE",
	PR_GET_THP_DISABLE:          "PR_GET_THP_DISABLE",
	PR_MPX_ENABLE_MANAGEMENT:    "PR_MPX_ENABLE_MANAGEMENT",
	PR_MPX_DISABLE_MANAGEMENT:   "PR_MPX_DISABLE_MANAGEMENT",
	PR_SET_FP_MODE:              "PR_SET_FP_MODE",
	PR_GET_FP_MODE:              "PR_GET_FP_MODE",
	PR_CAP_AMBIENT:              "PR_CAP_AMBIENT",
	PR_SVE_SET_VL:               "PR_SVE_SET_VL",
	PR_SVE_GET_VL:               "PR_SVE_GET_VL",
	PR_GET_SPECULATION_CTRL:     "PR_GET_SPECULATION_CTRL",
	PR_SET_SPECULATION_CTRL:     "PR_SET_SPECULATION_CTRL",
	PR_PAC_RESET_KEYS:           "PR_PAC_RESET_KEYS",
	PR_SET_TAGGED_ADDR_CTRL:     "PR_SET_TAGGED_ADDR_CTRL",
	PR_GET_TAGGED_ADDR_CTRL:     "PR_GET_TAGGED_ADDR_CTRL",
}

func (p PrctlOptionArgument) String() string {

	var res string
	if opName, ok := prctlOptionStringMap[p]; ok {
		res = opName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

var prctlOptionsMap = map[uint64]PrctlOptionArgument{
	PR_SET_PDEATHSIG.Value():            PR_SET_PDEATHSIG,
	PR_GET_PDEATHSIG.Value():            PR_GET_PDEATHSIG,
	PR_GET_DUMPABLE.Value():             PR_GET_DUMPABLE,
	PR_SET_DUMPABLE.Value():             PR_SET_DUMPABLE,
	PR_GET_UNALIGN.Value():              PR_GET_UNALIGN,
	PR_SET_UNALIGN.Value():              PR_SET_UNALIGN,
	PR_GET_KEEPCAPS.Value():             PR_GET_KEEPCAPS,
	PR_SET_KEEPCAPS.Value():             PR_SET_KEEPCAPS,
	PR_GET_FPEMU.Value():                PR_GET_FPEMU,
	PR_SET_FPEMU.Value():                PR_SET_FPEMU,
	PR_GET_FPEXC.Value():                PR_GET_FPEXC,
	PR_SET_FPEXC.Value():                PR_SET_FPEXC,
	PR_GET_TIMING.Value():               PR_GET_TIMING,
	PR_SET_TIMING.Value():               PR_SET_TIMING,
	PR_SET_NAME.Value():                 PR_SET_NAME,
	PR_GET_NAME.Value():                 PR_GET_NAME,
	PR_GET_ENDIAN.Value():               PR_GET_ENDIAN,
	PR_SET_ENDIAN.Value():               PR_SET_ENDIAN,
	PR_GET_SECCOMP.Value():              PR_GET_SECCOMP,
	PR_SET_SECCOMP.Value():              PR_SET_SECCOMP,
	PR_CAPBSET_READ.Value():             PR_CAPBSET_READ,
	PR_CAPBSET_DROP.Value():             PR_CAPBSET_DROP,
	PR_GET_TSC.Value():                  PR_GET_TSC,
	PR_SET_TSC.Value():                  PR_SET_TSC,
	PR_GET_SECUREBITS.Value():           PR_GET_SECUREBITS,
	PR_SET_SECUREBITS.Value():           PR_SET_SECUREBITS,
	PR_SET_TIMERSLACK.Value():           PR_SET_TIMERSLACK,
	PR_GET_TIMERSLACK.Value():           PR_GET_TIMERSLACK,
	PR_TASK_PERF_EVENTS_DISABLE.Value(): PR_TASK_PERF_EVENTS_DISABLE,
	PR_TASK_PERF_EVENTS_ENABLE.Value():  PR_TASK_PERF_EVENTS_ENABLE,
	PR_MCE_KILL.Value():                 PR_MCE_KILL,
	PR_MCE_KILL_GET.Value():             PR_MCE_KILL_GET,
	PR_SET_MM.Value():                   PR_SET_MM,
	PR_SET_CHILD_SUBREAPER.Value():      PR_SET_CHILD_SUBREAPER,
	PR_GET_CHILD_SUBREAPER.Value():      PR_GET_CHILD_SUBREAPER,
	PR_SET_NO_NEW_PRIVS.Value():         PR_SET_NO_NEW_PRIVS,
	PR_GET_NO_NEW_PRIVS.Value():         PR_GET_NO_NEW_PRIVS,
	PR_GET_TID_ADDRESS.Value():          PR_GET_TID_ADDRESS,
	PR_SET_THP_DISABLE.Value():          PR_SET_THP_DISABLE,
	PR_GET_THP_DISABLE.Value():          PR_GET_THP_DISABLE,
	PR_MPX_ENABLE_MANAGEMENT.Value():    PR_MPX_ENABLE_MANAGEMENT,
	PR_MPX_DISABLE_MANAGEMENT.Value():   PR_MPX_DISABLE_MANAGEMENT,
	PR_SET_FP_MODE.Value():              PR_SET_FP_MODE,
	PR_GET_FP_MODE.Value():              PR_GET_FP_MODE,
	PR_CAP_AMBIENT.Value():              PR_CAP_AMBIENT,
	PR_SVE_SET_VL.Value():               PR_SVE_SET_VL,
	PR_SVE_GET_VL.Value():               PR_SVE_GET_VL,
	PR_GET_SPECULATION_CTRL.Value():     PR_GET_SPECULATION_CTRL,
	PR_SET_SPECULATION_CTRL.Value():     PR_SET_SPECULATION_CTRL,
	PR_PAC_RESET_KEYS.Value():           PR_PAC_RESET_KEYS,
	PR_SET_TAGGED_ADDR_CTRL.Value():     PR_SET_TAGGED_ADDR_CTRL,
	PR_GET_TAGGED_ADDR_CTRL.Value():     PR_GET_TAGGED_ADDR_CTRL,
}

// ParsePrctlOption parses the `option` argument of the `prctl` syscall
// http://man7.org/linux/man-pages/man2/prctl.2.html
func ParsePrctlOption(rawValue uint64) (PrctlOptionArgument, error) {

	v, ok := prctlOptionsMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid prctl option value: %d", rawValue)
	}
	return v, nil
}

type BPFCommandArgument uint64

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

func (b BPFCommandArgument) Value() uint64 { return uint64(b) }

var bpfCmdStringMap = map[BPFCommandArgument]string{
	BPF_MAP_CREATE:                  "BPF_MAP_CREATE",
	BPF_MAP_LOOKUP_ELEM:             "BPF_MAP_LOOKUP_ELEM",
	BPF_MAP_UPDATE_ELEM:             "BPF_MAP_UPDATE_ELEM",
	BPF_MAP_DELETE_ELEM:             "BPF_MAP_DELETE_ELEM",
	BPF_MAP_GET_NEXT_KEY:            "BPF_MAP_GET_NEXT_KEY",
	BPF_PROG_LOAD:                   "BPF_PROG_LOAD",
	BPF_OBJ_PIN:                     "BPF_OBJ_PIN",
	BPF_OBJ_GET:                     "BPF_OBJ_GET",
	BPF_PROG_ATTACH:                 "BPF_PROG_ATTACH",
	BPF_PROG_DETACH:                 "BPF_PROG_DETACH",
	BPF_PROG_TEST_RUN:               "BPF_PROG_TEST_RUN",
	BPF_PROG_GET_NEXT_ID:            "BPF_PROG_GET_NEXT_ID",
	BPF_MAP_GET_NEXT_ID:             "BPF_MAP_GET_NEXT_ID",
	BPF_PROG_GET_FD_BY_ID:           "BPF_PROG_GET_FD_BY_ID",
	BPF_MAP_GET_FD_BY_ID:            "BPF_MAP_GET_FD_BY_ID",
	BPF_OBJ_GET_INFO_BY_FD:          "BPF_OBJ_GET_INFO_BY_FD",
	BPF_PROG_QUERY:                  "BPF_PROG_QUERY",
	BPF_RAW_TRACEPOINT_OPEN:         "BPF_RAW_TRACEPOINT_OPEN",
	BPF_BTF_LOAD:                    "BPF_BTF_LOAD",
	BPF_BTF_GET_FD_BY_ID:            "BPF_BTF_GET_FD_BY_ID",
	BPF_TASK_FD_QUERY:               "BPF_TASK_FD_QUERY",
	BPF_MAP_LOOKUP_AND_DELETE_ELEM:  "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	BPF_MAP_FREEZE:                  "BPF_MAP_FREEZE",
	BPF_BTF_GET_NEXT_ID:             "BPF_BTF_GET_NEXT_ID",
	BPF_MAP_LOOKUP_BATCH:            "BPF_MAP_LOOKUP_BATCH",
	BPF_MAP_LOOKUP_AND_DELETE_BATCH: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	BPF_MAP_UPDATE_BATCH:            "BPF_MAP_UPDATE_BATCH",
	BPF_MAP_DELETE_BATCH:            "BPF_MAP_DELETE_BATCH",
	BPF_LINK_CREATE:                 "BPF_LINK_CREATE",
	BPF_LINK_UPDATE:                 "BPF_LINK_UPDATE",
	BPF_LINK_GET_FD_BY_ID:           "BPF_LINK_GET_FD_BY_ID",
	BPF_LINK_GET_NEXT_ID:            "BPF_LINK_GET_NEXT_ID",
	BPF_ENABLE_STATS:                "BPF_ENABLE_STATS",
	BPF_ITER_CREATE:                 "BPF_ITER_CREATE",
	BPF_LINK_DETACH:                 "BPF_LINK_DETACH",
}

// String parses the `cmd` argument of the `bpf` syscall
// https://man7.org/linux/man-pages/man2/bpf.2.html
func (b BPFCommandArgument) String() string {

	var res string
	if cmdName, ok := bpfCmdStringMap[b]; ok {
		res = cmdName
	} else {
		res = strconv.Itoa(int(b))
	}

	return res
}

var bpfCmdMap = map[uint64]BPFCommandArgument{
	BPF_MAP_CREATE.Value():                  BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM.Value():             BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM.Value():             BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM.Value():             BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY.Value():            BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD.Value():                   BPF_PROG_LOAD,
	BPF_OBJ_PIN.Value():                     BPF_OBJ_PIN,
	BPF_OBJ_GET.Value():                     BPF_OBJ_GET,
	BPF_PROG_ATTACH.Value():                 BPF_PROG_ATTACH,
	BPF_PROG_DETACH.Value():                 BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN.Value():               BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID.Value():            BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID.Value():             BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID.Value():           BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID.Value():            BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD.Value():          BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY.Value():                  BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN.Value():         BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD.Value():                    BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID.Value():            BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY.Value():               BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM.Value():  BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE.Value():                  BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID.Value():             BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH.Value():            BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH.Value(): BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH.Value():            BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH.Value():            BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE.Value():                 BPF_LINK_CREATE,
	BPF_LINK_UPDATE.Value():                 BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID.Value():           BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID.Value():            BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS.Value():                BPF_ENABLE_STATS,
	BPF_ITER_CREATE.Value():                 BPF_ITER_CREATE,
	BPF_LINK_DETACH.Value():                 BPF_LINK_DETACH,
}

// ParseBPFCmd parses the raw value of the `cmd` argument of the `bpf` syscall
// https://man7.org/linux/man-pages/man2/bpf.2.html
func ParseBPFCmd(cmd uint64) (BPFCommandArgument, error) {
	v, ok := bpfCmdMap[cmd]
	if !ok {
		return 0, fmt.Errorf("not a valid  BPF command argument: %d", cmd)
	}
	return v, nil
}

type PtraceRequestArgument uint64

var (
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
	PTRACE_GET_SYSCALL_INFO     PtraceRequestArgument = 0x420e
)

func (p PtraceRequestArgument) Value() uint64 { return uint64(p) }

var ptraceRequestStringMap = map[PtraceRequestArgument]string{
	PTRACE_TRACEME:              "PTRACE_TRACEME",
	PTRACE_PEEKTEXT:             "PTRACE_PEEKTEXT",
	PTRACE_PEEKDATA:             "PTRACE_PEEKDATA",
	PTRACE_PEEKUSER:             "PTRACE_PEEKUSER",
	PTRACE_POKETEXT:             "PTRACE_POKETEXT",
	PTRACE_POKEDATA:             "PTRACE_POKEDATA",
	PTRACE_POKEUSER:             "PTRACE_POKEUSER",
	PTRACE_CONT:                 "PTRACE_CONT",
	PTRACE_KILL:                 "PTRACE_KILL",
	PTRACE_SINGLESTEP:           "PTRACE_SINGLESTEP",
	PTRACE_GETREGS:              "PTRACE_GETREGS",
	PTRACE_SETREGS:              "PTRACE_SETREGS",
	PTRACE_GETFPREGS:            "PTRACE_GETFPREGS",
	PTRACE_SETFPREGS:            "PTRACE_SETFPREGS",
	PTRACE_ATTACH:               "PTRACE_ATTACH",
	PTRACE_DETACH:               "PTRACE_DETACH",
	PTRACE_GETFPXREGS:           "PTRACE_GETFPXREGS",
	PTRACE_SETFPXREGS:           "PTRACE_SETFPXREGS",
	PTRACE_SYSCALL:              "PTRACE_SYSCALL",
	PTRACE_SETOPTIONS:           "PTRACE_SETOPTIONS",
	PTRACE_GETEVENTMSG:          "PTRACE_GETEVENTMSG",
	PTRACE_GETSIGINFO:           "PTRACE_GETSIGINFO",
	PTRACE_SETSIGINFO:           "PTRACE_SETSIGINFO",
	PTRACE_GETREGSET:            "PTRACE_GETREGSET",
	PTRACE_SETREGSET:            "PTRACE_SETREGSET",
	PTRACE_SEIZE:                "PTRACE_SEIZE",
	PTRACE_INTERRUPT:            "PTRACE_INTERRUPT",
	PTRACE_LISTEN:               "PTRACE_LISTEN",
	PTRACE_PEEKSIGINFO:          "PTRACE_PEEKSIGINFO",
	PTRACE_GETSIGMASK:           "PTRACE_GETSIGMASK",
	PTRACE_SETSIGMASK:           "PTRACE_SETSIGMASK",
	PTRACE_SECCOMP_GET_FILTER:   "PTRACE_SECCOMP_GET_FILTER",
	PTRACE_SECCOMP_GET_METADATA: "PTRACE_SECCOMP_GET_METADATA",
	PTRACE_GET_SYSCALL_INFO:     "PTRACE_GET_SYSCALL_INFO",
}

func (p PtraceRequestArgument) String() string {
	var res string
	if reqName, ok := ptraceRequestStringMap[p]; ok {
		res = reqName
	} else {
		res = strconv.Itoa(int(p))
	}

	return res
}

var ptraceRequestArgMap = map[uint64]PtraceRequestArgument{
	PTRACE_TRACEME.Value():              PTRACE_TRACEME,
	PTRACE_PEEKTEXT.Value():             PTRACE_PEEKTEXT,
	PTRACE_PEEKDATA.Value():             PTRACE_PEEKDATA,
	PTRACE_PEEKUSER.Value():             PTRACE_PEEKUSER,
	PTRACE_POKETEXT.Value():             PTRACE_POKETEXT,
	PTRACE_POKEDATA.Value():             PTRACE_POKEDATA,
	PTRACE_POKEUSER.Value():             PTRACE_POKEUSER,
	PTRACE_CONT.Value():                 PTRACE_CONT,
	PTRACE_KILL.Value():                 PTRACE_KILL,
	PTRACE_SINGLESTEP.Value():           PTRACE_SINGLESTEP,
	PTRACE_GETREGS.Value():              PTRACE_GETREGS,
	PTRACE_SETREGS.Value():              PTRACE_SETREGS,
	PTRACE_GETFPREGS.Value():            PTRACE_GETFPREGS,
	PTRACE_SETFPREGS.Value():            PTRACE_SETFPREGS,
	PTRACE_ATTACH.Value():               PTRACE_ATTACH,
	PTRACE_DETACH.Value():               PTRACE_DETACH,
	PTRACE_GETFPXREGS.Value():           PTRACE_GETFPXREGS,
	PTRACE_SETFPXREGS.Value():           PTRACE_SETFPXREGS,
	PTRACE_SYSCALL.Value():              PTRACE_SYSCALL,
	PTRACE_SETOPTIONS.Value():           PTRACE_SETOPTIONS,
	PTRACE_GETEVENTMSG.Value():          PTRACE_GETEVENTMSG,
	PTRACE_GETSIGINFO.Value():           PTRACE_GETSIGINFO,
	PTRACE_SETSIGINFO.Value():           PTRACE_SETSIGINFO,
	PTRACE_GETREGSET.Value():            PTRACE_GETREGSET,
	PTRACE_SETREGSET.Value():            PTRACE_SETREGSET,
	PTRACE_SEIZE.Value():                PTRACE_SEIZE,
	PTRACE_INTERRUPT.Value():            PTRACE_INTERRUPT,
	PTRACE_LISTEN.Value():               PTRACE_LISTEN,
	PTRACE_PEEKSIGINFO.Value():          PTRACE_PEEKSIGINFO,
	PTRACE_GETSIGMASK.Value():           PTRACE_GETSIGMASK,
	PTRACE_SETSIGMASK.Value():           PTRACE_SETSIGMASK,
	PTRACE_SECCOMP_GET_FILTER.Value():   PTRACE_SECCOMP_GET_FILTER,
	PTRACE_SECCOMP_GET_METADATA.Value(): PTRACE_SECCOMP_GET_METADATA,
	PTRACE_GET_SYSCALL_INFO.Value():     PTRACE_GET_SYSCALL_INFO,
}

func ParsePtraceRequestArgument(rawValue uint64) (PtraceRequestArgument, error) {

	if reqName, ok := ptraceRequestArgMap[rawValue]; ok {
		return reqName, nil
	}
	return 0, fmt.Errorf("not a valid ptrace request value: %d", rawValue)
}

type SocketDomainArgument uint64

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

func (s SocketDomainArgument) Value() uint64 { return uint64(s) }

var socketDomainStringMap = map[SocketDomainArgument]string{
	AF_UNSPEC:     "AF_UNSPEC",
	AF_UNIX:       "AF_UNIX",
	AF_INET:       "AF_INET",
	AF_AX25:       "AF_AX25",
	AF_IPX:        "AF_IPX",
	AF_APPLETALK:  "AF_APPLETALK",
	AF_NETROM:     "AF_NETROM",
	AF_BRIDGE:     "AF_BRIDGE",
	AF_ATMPVC:     "AF_ATMPVC",
	AF_X25:        "AF_X25",
	AF_INET6:      "AF_INET6",
	AF_ROSE:       "AF_ROSE",
	AF_DECnet:     "AF_DECnet",
	AF_NETBEUI:    "AF_NETBEUI",
	AF_SECURITY:   "AF_SECURITY",
	AF_KEY:        "AF_KEY",
	AF_NETLINK:    "AF_NETLINK",
	AF_PACKET:     "AF_PACKET",
	AF_ASH:        "AF_ASH",
	AF_ECONET:     "AF_ECONET",
	AF_ATMSVC:     "AF_ATMSVC",
	AF_RDS:        "AF_RDS",
	AF_SNA:        "AF_SNA",
	AF_IRDA:       "AF_IRDA",
	AF_PPPOX:      "AF_PPPOX",
	AF_WANPIPE:    "AF_WANPIPE",
	AF_LLC:        "AF_LLC",
	AF_IB:         "AF_IB",
	AF_MPLS:       "AF_MPLS",
	AF_CAN:        "AF_CAN",
	AF_TIPC:       "AF_TIPC",
	AF_BLUETOOTH:  "AF_BLUETOOTH",
	AF_IUCV:       "AF_IUCV",
	AF_RXRPC:      "AF_RXRPC",
	AF_ISDN:       "AF_ISDN",
	AF_PHONET:     "AF_PHONET",
	AF_IEEE802154: "AF_IEEE802154",
	AF_CAIF:       "AF_CAIF",
	AF_ALG:        "AF_ALG",
	AF_NFC:        "AF_NFC",
	AF_VSOCK:      "AF_VSOCK",
	AF_KCM:        "AF_KCM",
	AF_QIPCRTR:    "AF_QIPCRTR",
	AF_SMC:        "AF_SMC",
	AF_XDP:        "AF_XDP",
}

// String parses the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func (s SocketDomainArgument) String() string {
	var res string

	if sdName, ok := socketDomainStringMap[s]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(s))
	}

	return res
}

var socketDomainMap = map[uint64]SocketDomainArgument{
	AF_UNSPEC.Value():     AF_UNSPEC,
	AF_UNIX.Value():       AF_UNIX,
	AF_INET.Value():       AF_INET,
	AF_AX25.Value():       AF_AX25,
	AF_IPX.Value():        AF_IPX,
	AF_APPLETALK.Value():  AF_APPLETALK,
	AF_NETROM.Value():     AF_NETROM,
	AF_BRIDGE.Value():     AF_BRIDGE,
	AF_ATMPVC.Value():     AF_ATMPVC,
	AF_X25.Value():        AF_X25,
	AF_INET6.Value():      AF_INET6,
	AF_ROSE.Value():       AF_ROSE,
	AF_DECnet.Value():     AF_DECnet,
	AF_NETBEUI.Value():    AF_NETBEUI,
	AF_SECURITY.Value():   AF_SECURITY,
	AF_KEY.Value():        AF_KEY,
	AF_NETLINK.Value():    AF_NETLINK,
	AF_PACKET.Value():     AF_PACKET,
	AF_ASH.Value():        AF_ASH,
	AF_ECONET.Value():     AF_ECONET,
	AF_ATMSVC.Value():     AF_ATMSVC,
	AF_RDS.Value():        AF_RDS,
	AF_SNA.Value():        AF_SNA,
	AF_IRDA.Value():       AF_IRDA,
	AF_PPPOX.Value():      AF_PPPOX,
	AF_WANPIPE.Value():    AF_WANPIPE,
	AF_LLC.Value():        AF_LLC,
	AF_IB.Value():         AF_IB,
	AF_MPLS.Value():       AF_MPLS,
	AF_CAN.Value():        AF_CAN,
	AF_TIPC.Value():       AF_TIPC,
	AF_BLUETOOTH.Value():  AF_BLUETOOTH,
	AF_IUCV.Value():       AF_IUCV,
	AF_RXRPC.Value():      AF_RXRPC,
	AF_ISDN.Value():       AF_ISDN,
	AF_PHONET.Value():     AF_PHONET,
	AF_IEEE802154.Value(): AF_IEEE802154,
	AF_CAIF.Value():       AF_CAIF,
	AF_ALG.Value():        AF_ALG,
	AF_NFC.Value():        AF_NFC,
	AF_VSOCK.Value():      AF_VSOCK,
	AF_KCM.Value():        AF_KCM,
	AF_QIPCRTR.Value():    AF_QIPCRTR,
	AF_SMC.Value():        AF_SMC,
	AF_XDP.Value():        AF_XDP,
}

func ParseSocketDomainArgument(rawValue uint64) (SocketDomainArgument, error) {

	v, ok := socketDomainMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

type SocketTypeArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	SOCK_STREAM    SocketTypeArgument = SocketTypeArgument{rawValue: 1, stringValue: "SOCK_STREAM"}
	SOCK_DGRAM     SocketTypeArgument = SocketTypeArgument{rawValue: 2, stringValue: "SOCK_DGRAM"}
	SOCK_RAW       SocketTypeArgument = SocketTypeArgument{rawValue: 3, stringValue: "SOCK_RAW"}
	SOCK_RDM       SocketTypeArgument = SocketTypeArgument{rawValue: 4, stringValue: "SOCK_RDM"}
	SOCK_SEQPACKET SocketTypeArgument = SocketTypeArgument{rawValue: 5, stringValue: "SOCK_SEQPACKET"}
	SOCK_DCCP      SocketTypeArgument = SocketTypeArgument{rawValue: 6, stringValue: "SOCK_DCCP"}
	SOCK_PACKET    SocketTypeArgument = SocketTypeArgument{rawValue: 10, stringValue: "SOCK_PACKET"}
	SOCK_NONBLOCK  SocketTypeArgument = SocketTypeArgument{rawValue: 000004000, stringValue: "SOCK_NONBLOCK"}
	SOCK_CLOEXEC   SocketTypeArgument = SocketTypeArgument{rawValue: 002000000, stringValue: "SOCK_CLOEXEC"}
)

func (s SocketTypeArgument) Value() uint64  { return s.rawValue }
func (s SocketTypeArgument) String() string { return s.stringValue }

var socketTypeMap = map[uint64]SocketTypeArgument{
	SOCK_STREAM.Value():    SOCK_STREAM,
	SOCK_DGRAM.Value():     SOCK_DGRAM,
	SOCK_RAW.Value():       SOCK_RAW,
	SOCK_RDM.Value():       SOCK_RDM,
	SOCK_SEQPACKET.Value(): SOCK_SEQPACKET,
	SOCK_DCCP.Value():      SOCK_DCCP,
	SOCK_PACKET.Value():    SOCK_PACKET,
}

// ParseSocketType parses the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func ParseSocketType(rawValue uint64) (SocketTypeArgument, error) {
	var f []string

	if stName, ok := socketTypeMap[rawValue&0xf]; ok {
		f = append(f, stName.String())
	} else {
		f = append(f, strconv.Itoa(int(rawValue)))
	}

	if OptionAreContainedInArgument(rawValue, SOCK_NONBLOCK) {
		f = append(f, "SOCK_NONBLOCK")
	}
	if OptionAreContainedInArgument(rawValue, SOCK_CLOEXEC) {
		f = append(f, "SOCK_CLOEXEC")
	}

	return SocketTypeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type InodeModeArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	S_IFSOCK InodeModeArgument = InodeModeArgument{stringValue: "S_IFSOCK", rawValue: 0140000}
	S_IFLNK  InodeModeArgument = InodeModeArgument{stringValue: "S_IFLNK", rawValue: 0120000}
	S_IFREG  InodeModeArgument = InodeModeArgument{stringValue: "S_IFREG", rawValue: 0100000}
	S_IFBLK  InodeModeArgument = InodeModeArgument{stringValue: "S_IFBLK", rawValue: 060000}
	S_IFDIR  InodeModeArgument = InodeModeArgument{stringValue: "S_IFDIR", rawValue: 040000}
	S_IFCHR  InodeModeArgument = InodeModeArgument{stringValue: "S_IFCHR", rawValue: 020000}
	S_IFIFO  InodeModeArgument = InodeModeArgument{stringValue: "S_IFIFO", rawValue: 010000}
	S_IRWXU  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXU", rawValue: 00700}
	S_IRUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IRUSR", rawValue: 00400}
	S_IWUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IWUSR", rawValue: 00200}
	S_IXUSR  InodeModeArgument = InodeModeArgument{stringValue: "S_IXUSR", rawValue: 00100}
	S_IRWXG  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXG", rawValue: 00070}
	S_IRGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IRGRP", rawValue: 00040}
	S_IWGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IWGRP", rawValue: 00020}
	S_IXGRP  InodeModeArgument = InodeModeArgument{stringValue: "S_IXGRP", rawValue: 00010}
	S_IRWXO  InodeModeArgument = InodeModeArgument{stringValue: "S_IRWXO", rawValue: 00007}
	S_IROTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IROTH", rawValue: 00004}
	S_IWOTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IWOTH", rawValue: 00002}
	S_IXOTH  InodeModeArgument = InodeModeArgument{stringValue: "S_IXOTH", rawValue: 00001}
)

func (mode InodeModeArgument) Value() uint64  { return mode.rawValue }
func (mode InodeModeArgument) String() string { return mode.stringValue }

func ParseInodeMode(rawValue uint64) (InodeModeArgument, error) {
	var f []string

	// File Type
	switch {
	case OptionAreContainedInArgument(rawValue, S_IFSOCK):
		f = append(f, S_IFSOCK.String())
	case OptionAreContainedInArgument(rawValue, S_IFLNK):
		f = append(f, S_IFLNK.String())
	case OptionAreContainedInArgument(rawValue, S_IFREG):
		f = append(f, S_IFREG.String())
	case OptionAreContainedInArgument(rawValue, S_IFBLK):
		f = append(f, S_IFBLK.String())
	case OptionAreContainedInArgument(rawValue, S_IFDIR):
		f = append(f, S_IFDIR.String())
	case OptionAreContainedInArgument(rawValue, S_IFCHR):
		f = append(f, S_IFCHR.String())
	case OptionAreContainedInArgument(rawValue, S_IFIFO):
		f = append(f, S_IFIFO.String())
	}

	// File Mode
	// Owner
	if OptionAreContainedInArgument(rawValue, S_IRWXU) {
		f = append(f, S_IRWXU.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IRUSR) {
			f = append(f, S_IRUSR.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWUSR) {
			f = append(f, S_IWUSR.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXUSR) {
			f = append(f, S_IXUSR.String())
		}
	}
	// Group
	if OptionAreContainedInArgument(rawValue, S_IRWXG) {
		f = append(f, S_IRWXG.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IRGRP) {
			f = append(f, S_IRGRP.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWGRP) {
			f = append(f, S_IWGRP.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXGRP) {
			f = append(f, S_IXGRP.String())
		}
	}
	// Others
	if OptionAreContainedInArgument(rawValue, S_IRWXO) {
		f = append(f, S_IRWXO.String())
	} else {
		if OptionAreContainedInArgument(rawValue, S_IROTH) {
			f = append(f, S_IROTH.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IWOTH) {
			f = append(f, S_IWOTH.String())
		}
		if OptionAreContainedInArgument(rawValue, S_IXOTH) {
			f = append(f, S_IXOTH.String())
		}
	}

	return InodeModeArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}, nil
}

type MmapProtArgument struct {
	rawValue    uint64
	stringValue string
}

var (
	PROT_READ      MmapProtArgument = MmapProtArgument{stringValue: "PROT_READ", rawValue: 0x1}
	PROT_WRITE     MmapProtArgument = MmapProtArgument{stringValue: "PROT_WRITE", rawValue: 0x2}
	PROT_EXEC      MmapProtArgument = MmapProtArgument{stringValue: "PROT_EXEC", rawValue: 0x4}
	PROT_SEM       MmapProtArgument = MmapProtArgument{stringValue: "PROT_SEM", rawValue: 0x8}
	PROT_NONE      MmapProtArgument = MmapProtArgument{stringValue: "PROT_NONE", rawValue: 0x0}
	PROT_GROWSDOWN MmapProtArgument = MmapProtArgument{stringValue: "PROT_GROWSDOWN", rawValue: 0x01000000}
	PROT_GROWSUP   MmapProtArgument = MmapProtArgument{stringValue: "PROT_GROWSUP", rawValue: 0x02000000}
)

func (p MmapProtArgument) Value() uint64  { return p.rawValue }
func (p MmapProtArgument) String() string { return p.stringValue }

// ParseMmapProt parses the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func ParseMmapProt(rawValue uint64) MmapProtArgument {
	var f []string
	if rawValue == PROT_NONE.Value() {
		f = append(f, PROT_NONE.String())
	} else {
		if OptionAreContainedInArgument(rawValue, PROT_READ) {
			f = append(f, PROT_READ.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_WRITE) {
			f = append(f, PROT_WRITE.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_EXEC) {
			f = append(f, PROT_EXEC.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_SEM) {
			f = append(f, PROT_SEM.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_GROWSDOWN) {
			f = append(f, PROT_GROWSDOWN.String())
		}
		if OptionAreContainedInArgument(rawValue, PROT_GROWSUP) {
			f = append(f, PROT_GROWSUP.String())
		}
	}

	return MmapProtArgument{stringValue: strings.Join(f, "|"), rawValue: rawValue}
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

type SocketLevelArgument uint64

const (
	SOL_SOCKET   SocketLevelArgument = unix.SOL_SOCKET
	SOL_AAL      SocketLevelArgument = unix.SOL_AAL
	SOL_ALG      SocketLevelArgument = unix.SOL_ALG
	SOL_ATM      SocketLevelArgument = unix.SOL_ATM
	SOL_CAIF     SocketLevelArgument = unix.SOL_CAIF
	SOL_CAN_BASE SocketLevelArgument = unix.SOL_CAN_BASE
	SOL_CAN_RAW  SocketLevelArgument = unix.SOL_CAN_RAW
	SOL_DCCP     SocketLevelArgument = unix.SOL_DCCP
	SOL_DECNET   SocketLevelArgument = unix.SOL_DECNET
	SOL_ICMPV6   SocketLevelArgument = unix.SOL_ICMPV6
	SOL_IP       SocketLevelArgument = unix.SOL_IP
	SOL_IPV6     SocketLevelArgument = unix.SOL_IPV6
	SOL_IRDA     SocketLevelArgument = unix.SOL_IRDA
	SOL_IUCV     SocketLevelArgument = unix.SOL_IUCV
	SOL_KCM      SocketLevelArgument = unix.SOL_KCM
	SOL_LLC      SocketLevelArgument = unix.SOL_LLC
	SOL_NETBEUI  SocketLevelArgument = unix.SOL_NETBEUI
	SOL_NETLINK  SocketLevelArgument = unix.SOL_NETLINK
	SOL_NFC      SocketLevelArgument = unix.SOL_NFC
	SOL_PACKET   SocketLevelArgument = unix.SOL_PACKET
	SOL_PNPIPE   SocketLevelArgument = unix.SOL_PNPIPE
	SOL_PPPOL2TP SocketLevelArgument = unix.SOL_PPPOL2TP
	SOL_RAW      SocketLevelArgument = unix.SOL_RAW
	SOL_RDS      SocketLevelArgument = unix.SOL_RDS
	SOL_RXRPC    SocketLevelArgument = unix.SOL_RXRPC
	SOL_TCP      SocketLevelArgument = unix.SOL_TCP
	SOL_TIPC     SocketLevelArgument = unix.SOL_TIPC
	SOL_TLS      SocketLevelArgument = unix.SOL_TLS
	SOL_X25      SocketLevelArgument = unix.SOL_X25
	SOL_XDP      SocketLevelArgument = unix.SOL_XDP

	// The following are newer, so aren't included in the unix package
	SOL_MCTCP SocketLevelArgument = 284
	SOL_MCTP  SocketLevelArgument = 285
	SOL_SMC   SocketLevelArgument = 286
)

func (socketLevel SocketLevelArgument) Value() uint64 { return uint64(socketLevel) }

var socketLevelStringMap = map[SocketLevelArgument]string{
	SOL_SOCKET:   "SOL_SOCKET",
	SOL_AAL:      "SOL_AAL",
	SOL_ALG:      "SOL_ALG",
	SOL_ATM:      "SOL_ATM",
	SOL_CAIF:     "SOL_CAIF",
	SOL_CAN_BASE: "SOL_CAN_BASE",
	SOL_CAN_RAW:  "SOL_CAN_RAW",
	SOL_DCCP:     "SOL_DCCP",
	SOL_DECNET:   "SOL_DECNET",
	SOL_ICMPV6:   "SOL_ICMPV6",
	SOL_IP:       "SOL_IP",
	SOL_IPV6:     "SOL_IPV6",
	SOL_IRDA:     "SOL_IRDA",
	SOL_IUCV:     "SOL_IUCV",
	SOL_KCM:      "SOL_KCM",
	SOL_LLC:      "SOL_LLC",
	SOL_NETBEUI:  "SOL_NETBEUI",
	SOL_NETLINK:  "SOL_NETLINK",
	SOL_NFC:      "SOL_NFC",
	SOL_PACKET:   "SOL_PACKET",
	SOL_PNPIPE:   "SOL_PNPIPE",
	SOL_PPPOL2TP: "SOL_PPPOL2TP",
	SOL_RAW:      "SOL_RAW",
	SOL_RDS:      "SOL_RDS",
	SOL_RXRPC:    "SOL_RXRPC",
	SOL_TCP:      "SOL_TCP",
	SOL_TIPC:     "SOL_TIPC",
	SOL_TLS:      "SOL_TLS",
	SOL_X25:      "SOL_X25",
	SOL_XDP:      "SOL_XDP",
	SOL_MCTCP:    "SOL_MCTCP",
	SOL_MCTP:     "SOL_MCTP",
	SOL_SMC:      "SOL_SMC",
}

func (socketLevel SocketLevelArgument) String() string {
	var res string

	if sdName, ok := socketLevelStringMap[socketLevel]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(socketLevel))
	}

	return res
}

var socketLevelMap = map[uint64]SocketLevelArgument{
	SOL_SOCKET.Value():   SOL_SOCKET,
	SOL_AAL.Value():      SOL_AAL,
	SOL_ALG.Value():      SOL_ALG,
	SOL_ATM.Value():      SOL_ATM,
	SOL_CAIF.Value():     SOL_CAIF,
	SOL_CAN_BASE.Value(): SOL_CAN_BASE,
	SOL_CAN_RAW.Value():  SOL_CAN_RAW,
	SOL_DCCP.Value():     SOL_DCCP,
	SOL_DECNET.Value():   SOL_DECNET,
	SOL_ICMPV6.Value():   SOL_ICMPV6,
	SOL_IP.Value():       SOL_IP,
	SOL_IPV6.Value():     SOL_IPV6,
	SOL_IRDA.Value():     SOL_IRDA,
	SOL_IUCV.Value():     SOL_IUCV,
	SOL_KCM.Value():      SOL_KCM,
	SOL_LLC.Value():      SOL_LLC,
	SOL_NETBEUI.Value():  SOL_NETBEUI,
	SOL_NETLINK.Value():  SOL_NETLINK,
	SOL_NFC.Value():      SOL_NFC,
	SOL_PACKET.Value():   SOL_PACKET,
	SOL_PNPIPE.Value():   SOL_PNPIPE,
	SOL_PPPOL2TP.Value(): SOL_PPPOL2TP,
	SOL_RAW.Value():      SOL_RAW,
	SOL_RDS.Value():      SOL_RDS,
	SOL_RXRPC.Value():    SOL_RXRPC,
	SOL_TCP.Value():      SOL_TCP,
	SOL_TIPC.Value():     SOL_TIPC,
	SOL_TLS.Value():      SOL_TLS,
	SOL_X25.Value():      SOL_X25,
	SOL_XDP.Value():      SOL_XDP,
	SOL_MCTCP.Value():    SOL_MCTCP,
	SOL_MCTP.Value():     SOL_MCTP,
	SOL_SMC.Value():      SOL_SMC,
}

// ParseSocketLevel parses the `level` argument of the `setsockopt` and `getsockopt` syscalls.
// https://man7.org/linux/man-pages/man2/setsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h
func ParseSocketLevel(rawValue uint64) (SocketLevelArgument, error) {

	v, ok := socketLevelMap[rawValue]
	if !ok {
		return 0, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

type SocketOptionArgument struct {
	value uint64
	name  string
}

var (
	SO_DEBUG                         = SocketOptionArgument{unix.SO_DEBUG, "SO_DEBUG"}
	SO_REUSEADDR                     = SocketOptionArgument{unix.SO_REUSEADDR, "SO_REUSEADDR"}
	SO_TYPE                          = SocketOptionArgument{unix.SO_TYPE, "SO_TYPE"}
	SO_ERROR                         = SocketOptionArgument{unix.SO_ERROR, "SO_ERROR"}
	SO_DONTROUTE                     = SocketOptionArgument{unix.SO_DONTROUTE, "SO_DONTROUTE"}
	SO_BROADCAST                     = SocketOptionArgument{unix.SO_BROADCAST, "SO_BROADCAST"}
	SO_SNDBUF                        = SocketOptionArgument{unix.SO_SNDBUF, "SO_SNDBUF"}
	SO_RCVBUF                        = SocketOptionArgument{unix.SO_RCVBUF, "SO_RCVBUF"}
	SO_SNDBUFFORCE                   = SocketOptionArgument{unix.SO_SNDBUFFORCE, "SO_SNDBUFFORCE"}
	SO_RCVBUFFORCE                   = SocketOptionArgument{unix.SO_RCVBUFFORCE, "SO_RCVBUFFORCE"}
	SO_KEEPALIVE                     = SocketOptionArgument{unix.SO_KEEPALIVE, "SO_KEEPALIVE"}
	SO_OOBINLINE                     = SocketOptionArgument{unix.SO_OOBINLINE, "SO_OOBINLINE"}
	SO_NO_CHECK                      = SocketOptionArgument{unix.SO_NO_CHECK, "SO_NO_CHECK"}
	SO_PRIORITY                      = SocketOptionArgument{unix.SO_PRIORITY, "SO_PRIORITY"}
	SO_LINGER                        = SocketOptionArgument{unix.SO_LINGER, "SO_LINGER"}
	SO_BSDCOMPAT                     = SocketOptionArgument{unix.SO_BSDCOMPAT, "SO_BSDCOMPAT"}
	SO_REUSEPORT                     = SocketOptionArgument{unix.SO_REUSEPORT, "SO_REUSEPORT"}
	SO_PASSCRED                      = SocketOptionArgument{unix.SO_PASSCRED, "SO_PASSCRED"}
	SO_PEERCRED                      = SocketOptionArgument{unix.SO_PEERCRED, "SO_PEERCRED"}
	SO_RCVLOWAT                      = SocketOptionArgument{unix.SO_RCVLOWAT, "SO_RCVLOWAT"}
	SO_SNDLOWAT                      = SocketOptionArgument{unix.SO_SNDLOWAT, "SO_SNDLOWAT"}
	SO_SECURITY_AUTHENTICATION       = SocketOptionArgument{unix.SO_SECURITY_AUTHENTICATION, "SO_SECURITY_AUTHENTICATION"}
	SO_SECURITY_ENCRYPTION_TRANSPORT = SocketOptionArgument{unix.SO_SECURITY_ENCRYPTION_TRANSPORT, "SO_SECURITY_ENCRYPTION_TRANSPORT"}
	SO_SECURITY_ENCRYPTION_NETWORK   = SocketOptionArgument{unix.SO_SECURITY_ENCRYPTION_NETWORK, "SO_SECURITY_ENCRYPTION_NETWORK"}
	SO_BINDTODEVICE                  = SocketOptionArgument{unix.SO_BINDTODEVICE, "SO_BINDTODEVICE"}
	SO_ATTACH_FILTER                 = SocketOptionArgument{unix.SO_ATTACH_FILTER, "SO_ATTACH_FILTER"}
	SO_GET_FILTER                    = SocketOptionArgument{unix.SO_GET_FILTER, "SO_GET_FILTER"}
	SO_DETACH_FILTER                 = SocketOptionArgument{unix.SO_DETACH_FILTER, "SO_DETACH_FILTER"}
	SO_PEERNAME                      = SocketOptionArgument{unix.SO_PEERNAME, "SO_PEERNAME"}
	SO_ACCEPTCONN                    = SocketOptionArgument{unix.SO_ACCEPTCONN, "SO_ACCEPTCONN"}
	SO_PEERSEC                       = SocketOptionArgument{unix.SO_PEERSEC, "SO_PEERSEC"}
	SO_PASSSEC                       = SocketOptionArgument{unix.SO_PASSSEC, "SO_PASSSEC"}
	SO_MARK                          = SocketOptionArgument{unix.SO_MARK, "SO_MARK"}
	SO_PROTOCOL                      = SocketOptionArgument{unix.SO_PROTOCOL, "SO_PROTOCOL"}
	SO_DOMAIN                        = SocketOptionArgument{unix.SO_DOMAIN, "SO_DOMAIN"}
	SO_RXQ_OVFL                      = SocketOptionArgument{unix.SO_RXQ_OVFL, "SO_RXQ_OVFL"}
	SO_WIFI_STATUS                   = SocketOptionArgument{unix.SO_WIFI_STATUS, "SO_WIFI_STATUS"}
	SO_PEEK_OFF                      = SocketOptionArgument{unix.SO_PEEK_OFF, "SO_PEEK_OFF"}
	SO_NOFCS                         = SocketOptionArgument{unix.SO_NOFCS, "SO_NOFCS"}
	SO_LOCK_FILTER                   = SocketOptionArgument{unix.SO_LOCK_FILTER, "SO_LOCK_FILTER"}
	SO_SELECT_ERR_QUEUE              = SocketOptionArgument{unix.SO_SELECT_ERR_QUEUE, "SO_SELECT_ERR_QUEUE"}
	SO_BUSY_POLL                     = SocketOptionArgument{unix.SO_BUSY_POLL, "SO_BUSY_POLL"}
	SO_MAX_PACING_RATE               = SocketOptionArgument{unix.SO_MAX_PACING_RATE, "SO_MAX_PACING_RATE"}
	SO_BPF_EXTENSIONS                = SocketOptionArgument{unix.SO_BPF_EXTENSIONS, "SO_BPF_EXTENSIONS"}
	SO_INCOMING_CPU                  = SocketOptionArgument{unix.SO_INCOMING_CPU, "SO_INCOMING_CPU"}
	SO_ATTACH_BPF                    = SocketOptionArgument{unix.SO_ATTACH_BPF, "SO_ATTACH_BPF"}
	SO_ATTACH_REUSEPORT_CBPF         = SocketOptionArgument{unix.SO_ATTACH_REUSEPORT_CBPF, "SO_ATTACH_REUSEPORT_CBPF"}
	SO_ATTACH_REUSEPORT_EBPF         = SocketOptionArgument{unix.SO_ATTACH_REUSEPORT_EBPF, "SO_ATTACH_REUSEPORT_EBPF"}
	SO_CNX_ADVICE                    = SocketOptionArgument{unix.SO_CNX_ADVICE, "SO_CNX_ADVICE"}
	SCM_TIMESTAMPING_OPT_STATS       = SocketOptionArgument{unix.SCM_TIMESTAMPING_OPT_STATS, "SCM_TIMESTAMPING_OPT_STATS"}
	SO_MEMINFO                       = SocketOptionArgument{unix.SO_MEMINFO, "SO_MEMINFO"}
	SO_INCOMING_NAPI_ID              = SocketOptionArgument{unix.SO_INCOMING_NAPI_ID, "SO_INCOMING_NAPI_ID"}
	SO_COOKIE                        = SocketOptionArgument{unix.SO_COOKIE, "SO_COOKIE"}
	SCM_TIMESTAMPING_PKTINFO         = SocketOptionArgument{unix.SCM_TIMESTAMPING_PKTINFO, "SCM_TIMESTAMPING_PKTINFO"}
	SO_PEERGROUPS                    = SocketOptionArgument{unix.SO_PEERGROUPS, "SO_PEERGROUPS"}
	SO_ZEROCOPY                      = SocketOptionArgument{unix.SO_ZEROCOPY, "SO_ZEROCOPY"}
	SO_TXTIME                        = SocketOptionArgument{unix.SO_TXTIME, "SO_TXTIME"}
	SO_BINDTOIFINDEX                 = SocketOptionArgument{unix.SO_BINDTOIFINDEX, "SO_BINDTOIFINDEX"}
	SO_TIMESTAMP_NEW                 = SocketOptionArgument{unix.SO_TIMESTAMP_NEW, "SO_TIMESTAMP_NEW"}
	SO_TIMESTAMPNS_NEW               = SocketOptionArgument{unix.SO_TIMESTAMPNS_NEW, "SO_TIMESTAMPNS_NEW"}
	SO_TIMESTAMPING_NEW              = SocketOptionArgument{unix.SO_TIMESTAMPING_NEW, "SO_TIMESTAMPING_NEW"}
	SO_RCVTIMEO_NEW                  = SocketOptionArgument{unix.SO_RCVTIMEO_NEW, "SO_RCVTIMEO_NEW"}
	SO_SNDTIMEO_NEW                  = SocketOptionArgument{unix.SO_SNDTIMEO_NEW, "SO_SNDTIMEO_NEW"}
	SO_DETACH_REUSEPORT_BPF          = SocketOptionArgument{unix.SO_DETACH_REUSEPORT_BPF, "SO_DETACH_REUSEPORT_BPF"}
	SO_PREFER_BUSY_POLL              = SocketOptionArgument{unix.SO_PREFER_BUSY_POLL, "SO_PREFER_BUSY_POLL"}
	SO_BUSY_POLL_BUDGET              = SocketOptionArgument{unix.SO_BUSY_POLL_BUDGET, "SO_BUSY_POLL_BUDGET"}
	SO_TIMESTAMP                     = SocketOptionArgument{unix.SO_TIMESTAMP, "SO_TIMESTAMP"}
	SO_TIMESTAMPNS                   = SocketOptionArgument{unix.SO_TIMESTAMPNS, "SO_TIMESTAMPNS"}
	SO_TIMESTAMPING                  = SocketOptionArgument{unix.SO_TIMESTAMPING, "SO_TIMESTAMPING"}
	SO_RCVTIMEO                      = SocketOptionArgument{unix.SO_RCVTIMEO, "SO_RCVTIMEO"}
	SO_SNDTIMEO                      = SocketOptionArgument{unix.SO_SNDTIMEO, "SO_SNDTIMEO"}

	// The following are newer, so aren't included in the unix package
	SO_NETNS_COOKIE SocketOptionArgument = SocketOptionArgument{71, "SO_NETNS_COOKIE"}
	SO_BUF_LOCK     SocketOptionArgument = SocketOptionArgument{72, "SO_BUF_LOCK"}
	SO_RESERVE_MEM  SocketOptionArgument = SocketOptionArgument{73, "SO_RESERVE_MEM"}
	SO_TXREHASH     SocketOptionArgument = SocketOptionArgument{74, "SO_TXREHASH"}
)

func (socketOption SocketOptionArgument) Value() uint64 { return socketOption.value }

func (socketOption SocketOptionArgument) String() string {
	return socketOption.name
}

var setSocketOptionMap = map[uint64]SocketOptionArgument{
	SO_DEBUG.Value():                         SO_DEBUG,
	SO_REUSEADDR.Value():                     SO_REUSEADDR,
	SO_TYPE.Value():                          SO_TYPE,
	SO_ERROR.Value():                         SO_ERROR,
	SO_DONTROUTE.Value():                     SO_DONTROUTE,
	SO_BROADCAST.Value():                     SO_BROADCAST,
	SO_SNDBUF.Value():                        SO_SNDBUF,
	SO_RCVBUF.Value():                        SO_RCVBUF,
	SO_SNDBUFFORCE.Value():                   SO_SNDBUFFORCE,
	SO_RCVBUFFORCE.Value():                   SO_RCVBUFFORCE,
	SO_KEEPALIVE.Value():                     SO_KEEPALIVE,
	SO_OOBINLINE.Value():                     SO_OOBINLINE,
	SO_NO_CHECK.Value():                      SO_NO_CHECK,
	SO_PRIORITY.Value():                      SO_PRIORITY,
	SO_LINGER.Value():                        SO_LINGER,
	SO_BSDCOMPAT.Value():                     SO_BSDCOMPAT,
	SO_REUSEPORT.Value():                     SO_REUSEPORT,
	SO_PASSCRED.Value():                      SO_PASSCRED,
	SO_PEERCRED.Value():                      SO_PEERCRED,
	SO_RCVLOWAT.Value():                      SO_RCVLOWAT,
	SO_SNDLOWAT.Value():                      SO_SNDLOWAT,
	SO_SECURITY_AUTHENTICATION.Value():       SO_SECURITY_AUTHENTICATION,
	SO_SECURITY_ENCRYPTION_TRANSPORT.Value(): SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK.Value():   SO_SECURITY_ENCRYPTION_NETWORK,
	SO_BINDTODEVICE.Value():                  SO_BINDTODEVICE,
	SO_ATTACH_FILTER.Value():                 SO_ATTACH_FILTER,
	SO_DETACH_FILTER.Value():                 SO_DETACH_FILTER,
	SO_PEERNAME.Value():                      SO_PEERNAME,
	SO_ACCEPTCONN.Value():                    SO_ACCEPTCONN,
	SO_PEERSEC.Value():                       SO_PEERSEC,
	SO_PASSSEC.Value():                       SO_PASSSEC,
	SO_MARK.Value():                          SO_MARK,
	SO_PROTOCOL.Value():                      SO_PROTOCOL,
	SO_DOMAIN.Value():                        SO_DOMAIN,
	SO_RXQ_OVFL.Value():                      SO_RXQ_OVFL,
	SO_WIFI_STATUS.Value():                   SO_WIFI_STATUS,
	SO_PEEK_OFF.Value():                      SO_PEEK_OFF,
	SO_NOFCS.Value():                         SO_NOFCS,
	SO_LOCK_FILTER.Value():                   SO_LOCK_FILTER,
	SO_SELECT_ERR_QUEUE.Value():              SO_SELECT_ERR_QUEUE,
	SO_BUSY_POLL.Value():                     SO_BUSY_POLL,
	SO_MAX_PACING_RATE.Value():               SO_MAX_PACING_RATE,
	SO_BPF_EXTENSIONS.Value():                SO_BPF_EXTENSIONS,
	SO_INCOMING_CPU.Value():                  SO_INCOMING_CPU,
	SO_ATTACH_BPF.Value():                    SO_ATTACH_BPF,
	SO_ATTACH_REUSEPORT_CBPF.Value():         SO_ATTACH_REUSEPORT_CBPF,
	SO_ATTACH_REUSEPORT_EBPF.Value():         SO_ATTACH_REUSEPORT_EBPF,
	SO_CNX_ADVICE.Value():                    SO_CNX_ADVICE,
	SCM_TIMESTAMPING_OPT_STATS.Value():       SCM_TIMESTAMPING_OPT_STATS,
	SO_MEMINFO.Value():                       SO_MEMINFO,
	SO_INCOMING_NAPI_ID.Value():              SO_INCOMING_NAPI_ID,
	SO_COOKIE.Value():                        SO_COOKIE,
	SCM_TIMESTAMPING_PKTINFO.Value():         SCM_TIMESTAMPING_PKTINFO,
	SO_PEERGROUPS.Value():                    SO_PEERGROUPS,
	SO_ZEROCOPY.Value():                      SO_ZEROCOPY,
	SO_TXTIME.Value():                        SO_TXTIME,
	SO_BINDTOIFINDEX.Value():                 SO_BINDTOIFINDEX,
	SO_TIMESTAMP_NEW.Value():                 SO_TIMESTAMP_NEW,
	SO_TIMESTAMPNS_NEW.Value():               SO_TIMESTAMPNS_NEW,
	SO_TIMESTAMPING_NEW.Value():              SO_TIMESTAMPING_NEW,
	SO_RCVTIMEO_NEW.Value():                  SO_RCVTIMEO_NEW,
	SO_SNDTIMEO_NEW.Value():                  SO_SNDTIMEO_NEW,
	SO_DETACH_REUSEPORT_BPF.Value():          SO_DETACH_REUSEPORT_BPF,
	SO_PREFER_BUSY_POLL.Value():              SO_PREFER_BUSY_POLL,
	SO_BUSY_POLL_BUDGET.Value():              SO_BUSY_POLL_BUDGET,
	SO_NETNS_COOKIE.Value():                  SO_NETNS_COOKIE,
	SO_BUF_LOCK.Value():                      SO_BUF_LOCK,
	SO_RESERVE_MEM.Value():                   SO_RESERVE_MEM,
	SO_TIMESTAMP.Value():                     SO_TIMESTAMP,
	SO_TIMESTAMPNS.Value():                   SO_TIMESTAMPNS,
	SO_TIMESTAMPING.Value():                  SO_TIMESTAMPING,
	SO_RCVTIMEO.Value():                      SO_RCVTIMEO,
	SO_SNDTIMEO.Value():                      SO_SNDTIMEO,
	SO_TXREHASH.Value():                      SO_TXREHASH,
}

var getSocketOptionMap = func(m map[uint64]SocketOptionArgument) map[uint64]SocketOptionArgument {
	newMap := make(map[uint64]SocketOptionArgument, len(m))
	for k, v := range m {
		newMap[k] = v
	}
	// Will override the value of SO_ATTACH_FILTER
	newMap[SO_GET_FILTER.Value()] = SO_GET_FILTER
	return newMap
}(setSocketOptionMap)

// ParseSetSocketOption parses the `optname` argument of the `setsockopt` syscall.
// https://man7.org/linux/man-pages/man2/setsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/socket.h
func ParseSetSocketOption(rawValue uint64) (SocketOptionArgument, error) {
	v, ok := setSocketOptionMap[rawValue]
	if !ok {
		return SocketOptionArgument{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

// ParseGetSocketOption parses the `optname` argument of the `getsockopt` syscall.
// https://man7.org/linux/man-pages/man2/getsockopt.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/socket.h
func ParseGetSocketOption(rawValue uint64) (SocketOptionArgument, error) {
	v, ok := getSocketOptionMap[rawValue]
	if !ok {
		return SocketOptionArgument{}, fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

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

func (b BPFProgType) Value() uint64 {
	return uint64(b)
}

func (b BPFProgType) String() string {
	x := map[BPFProgType]string{
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
	str, found := x[b]
	if !found {
		str = BPFProgTypeUnspec.String()
	}
	return str
}

var bpfProgTypeMap = map[uint64]BPFProgType{
	BPFProgTypeUnspec.Value():                BPFProgTypeUnspec,
	BPFProgTypeSocketFilter.Value():          BPFProgTypeSocketFilter,
	BPFProgTypeKprobe.Value():                BPFProgTypeKprobe,
	BPFProgTypeSchedCls.Value():              BPFProgTypeSchedCls,
	BPFProgTypeSchedAct.Value():              BPFProgTypeSchedAct,
	BPFProgTypeTracepoint.Value():            BPFProgTypeTracepoint,
	BPFProgTypeXdp.Value():                   BPFProgTypeXdp,
	BPFProgTypePerfEvent.Value():             BPFProgTypePerfEvent,
	BPFProgTypeCgroupSkb.Value():             BPFProgTypeCgroupSkb,
	BPFProgTypeCgroupSock.Value():            BPFProgTypeCgroupSock,
	BPFProgTypeLwtIn.Value():                 BPFProgTypeLwtIn,
	BPFProgTypeLwtOut.Value():                BPFProgTypeLwtOut,
	BPFProgTypeLwtXmit.Value():               BPFProgTypeLwtXmit,
	BPFProgTypeSockOps.Value():               BPFProgTypeSockOps,
	BPFProgTypeSkSkb.Value():                 BPFProgTypeSkSkb,
	BPFProgTypeCgroupDevice.Value():          BPFProgTypeCgroupDevice,
	BPFProgTypeSkMsg.Value():                 BPFProgTypeSkMsg,
	BPFProgTypeRawTracepoint.Value():         BPFProgTypeRawTracepoint,
	BPFProgTypeCgroupSockAddr.Value():        BPFProgTypeCgroupSockAddr,
	BPFProgTypeLwtSeg6Local.Value():          BPFProgTypeLwtSeg6Local,
	BPFProgTypeLircMode2.Value():             BPFProgTypeLircMode2,
	BPFProgTypeSkReuseport.Value():           BPFProgTypeSkReuseport,
	BPFProgTypeFlowDissector.Value():         BPFProgTypeFlowDissector,
	BPFProgTypeCgroupSysctl.Value():          BPFProgTypeCgroupSysctl,
	BPFProgTypeRawTracepointWritable.Value(): BPFProgTypeRawTracepointWritable,
	BPFProgTypeCgroupSockopt.Value():         BPFProgTypeCgroupSockopt,
	BPFProgTypeTracing.Value():               BPFProgTypeTracing,
	BPFProgTypeStructOps.Value():             BPFProgTypeStructOps,
	BPFProgTypeExt.Value():                   BPFProgTypeExt,
	BPFProgTypeLsm.Value():                   BPFProgTypeLsm,
	BPFProgTypeSkLookup.Value():              BPFProgTypeSkLookup,
	BPFProgTypeSyscall.Value():               BPFProgTypeSyscall,
}

func ParseBPFProgType(rawValue uint64) (BPFProgType, error) {
	v, ok := bpfProgTypeMap[rawValue]
	if !ok {
		return BPFProgType(0), fmt.Errorf("not a valid argument: %d", rawValue)
	}
	return v, nil
}

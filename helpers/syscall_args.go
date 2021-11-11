package helpers

const (
	// These values are copied from uapi/linux/sched.h
	CLONE_VM             uint64 = 0x00000100 /* set if VM shared between processes */
	CLONE_FS             uint64 = 0x00000200 /* set if fs info shared between processes */
	CLONE_FILES          uint64 = 0x00000400 /* set if open files shared between processes */
	CLONE_SIGHAND        uint64 = 0x00000800 /* set if signal handlers and blocked signals shared */
	CLONE_PIDFD          uint64 = 0x00001000 /* set if a pidfd should be placed in parent */
	CLONE_PTRACE         uint64 = 0x00002000 /* set if we want to let tracing continue on the child too */
	CLONE_VFORK          uint64 = 0x00004000 /* set if the parent wants the child to wake it up on mm_release */
	CLONE_PARENT         uint64 = 0x00008000 /* set if we want to have the same parent as the cloner */
	CLONE_THREAD         uint64 = 0x00010000 /* Same thread group? */
	CLONE_NEWNS          uint64 = 0x00020000 /* New mount namespace group */
	CLONE_SYSVSEM        uint64 = 0x00040000 /* share system V SEM_UNDO semantics */
	CLONE_SETTLS         uint64 = 0x00080000 /* create a new TLS for the child */
	CLONE_PARENT_SETTID  uint64 = 0x00100000 /* set the TID in the parent */
	CLONE_CHILD_CLEARTID uint64 = 0x00200000 /* clear the TID in the child */
	CLONE_DETACHED       uint64 = 0x00400000 /* Unused ignored */
	CLONE_UNTRACED       uint64 = 0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this clone */
	CLONE_CHILD_SETTID   uint64 = 0x01000000 /* set the TID in the child */
	CLONE_NEWCGROUP      uint64 = 0x02000000 /* New cgroup namespace */
	CLONE_NEWUTS         uint64 = 0x04000000 /* New utsname namespace */
	CLONE_NEWIPC         uint64 = 0x08000000 /* New ipc namespace */
	CLONE_NEWUSER        uint64 = 0x10000000 /* New user namespace */
	CLONE_NEWPID         uint64 = 0x20000000 /* New pid namespace */
	CLONE_NEWNET         uint64 = 0x40000000 /* New network namespace */
	CLONE_IO             uint64 = 0x80000000 /* Clone io context */

	// These values are copied from uapi/asm-generic/fcntl.h
	O_ACCMODE   uint64 = 00000003
	O_RDONLY    uint64 = 00000000
	O_WRONLY    uint64 = 00000001
	O_RDWR      uint64 = 00000002
	O_CREAT     uint64 = 00000100
	O_EXCL      uint64 = 00000200
	O_NOCTTY    uint64 = 00000400
	O_TRUNC     uint64 = 00001000
	O_APPEND    uint64 = 00002000
	O_NONBLOCK  uint64 = 00004000
	O_DSYNC     uint64 = 00010000
	O_SYNC      uint64 = 04010000
	O_ASYNC     uint64 = 020000
	FASYNC      uint64 = 00020000
	O_DIRECT    uint64 = 00040000
	O_LARGEFILE uint64 = 00100000
	O_DIRECTORY uint64 = 00200000
	O_NOFOLLOW  uint64 = 00400000
	O_NOATIME   uint64 = 01000000
	O_CLOEXEC   uint64 = 02000000
	O_PATH      uint64 = 040000000
	O_TMPFILE   uint64 = 020000000

	F_OK uint64 = 0
	X_OK uint64 = 1
	W_OK uint64 = 2
	R_OK uint64 = 4

	AT_SYMLINK_NOFOLLOW   uint64 = 0x100
	AT_EACCESS            uint64 = 0x200
	AT_REMOVEDIR          uint64 = 0x200
	AT_SYMLINK_FOLLOW     uint64 = 0x400
	AT_NO_AUTOMOUNT       uint64 = 0x800
	AT_EMPTY_PATH         uint64 = 0x1000
	AT_STATX_SYNC_TYPE    uint64 = 0x6000
	AT_STATX_SYNC_AS_STAT uint64 = 0x0000
	AT_STATX_FORCE_SYNC   uint64 = 0x2000
	AT_STATX_DONT_SYNC    uint64 = 0x4000
	AT_RECURSIVE          uint64 = 0x8000
)

// EventArgumentContainsOption checks whether the argument (rawArgument)
// contains the 'option' such as with flags passed to the clone flag.
// Typically linux syscalls have multiple options specified in a single
// argument via bitmasks, which this function checks for.
// It is meant to be used with the constants redefined in this package.
func EventArgumentContainsOption(option, rawArgument uint64) bool {
	return eventArgumentContainsOption(option, rawArgument)
}

func eventArgumentContainsOption(option, rawArgument uint64) bool {
	return option&rawArgument == option
}

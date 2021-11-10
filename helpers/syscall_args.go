package helpers

type CloneFlag uint64

const (
	// These values are copied from uapi/linux/sched.h
	CSIGNAL              CloneFlag = 0x000000ff /* signal mask to be sent at exit */
	CLONE_VM             CloneFlag = 0x00000100 /* set if VM shared between processes */
	CLONE_FS             CloneFlag = 0x00000200 /* set if fs info shared between processes */
	CLONE_FILES          CloneFlag = 0x00000400 /* set if open files shared between processes */
	CLONE_SIGHAND        CloneFlag = 0x00000800 /* set if signal handlers and blocked signals shared */
	CLONE_PIDFD          CloneFlag = 0x00001000 /* set if a pidfd should be placed in parent */
	CLONE_PTRACE         CloneFlag = 0x00002000 /* set if we want to let tracing continue on the child too */
	CLONE_VFORK          CloneFlag = 0x00004000 /* set if the parent wants the child to wake it up on mm_release */
	CLONE_PARENT         CloneFlag = 0x00008000 /* set if we want to have the same parent as the cloner */
	CLONE_THREAD         CloneFlag = 0x00010000 /* Same thread group? */
	CLONE_NEWNS          CloneFlag = 0x00020000 /* New mount namespace group */
	CLONE_SYSVSEM        CloneFlag = 0x00040000 /* share system V SEM_UNDO semantics */
	CLONE_SETTLS         CloneFlag = 0x00080000 /* create a new TLS for the child */
	CLONE_PARENT_SETTID  CloneFlag = 0x00100000 /* set the TID in the parent */
	CLONE_CHILD_CLEARTID CloneFlag = 0x00200000 /* clear the TID in the child */
	CLONE_DETACHED       CloneFlag = 0x00400000 /* Unused ignored */
	CLONE_UNTRACED       CloneFlag = 0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this clone */
	CLONE_CHILD_SETTID   CloneFlag = 0x01000000 /* set the TID in the child */
	CLONE_NEWCGROUP      CloneFlag = 0x02000000 /* New cgroup namespace */
	CLONE_NEWUTS         CloneFlag = 0x04000000 /* New utsname namespace */
	CLONE_NEWIPC         CloneFlag = 0x08000000 /* New ipc namespace */
	CLONE_NEWUSER        CloneFlag = 0x10000000 /* New user namespace */
	CLONE_NEWPID         CloneFlag = 0x20000000 /* New pid namespace */
	CLONE_NEWNET         CloneFlag = 0x40000000 /* New network namespace */
	CLONE_IO             CloneFlag = 0x80000000 /* Clone io context */
)

type OpenFlag uint64

const (
	// These values are copied from uapi/asm-generic/fcntl.h
	O_ACCMODE   OpenFlag = 00000003
	O_RDONLY    OpenFlag = 00000000
	O_WRONLY    OpenFlag = 00000001
	O_RDWR      OpenFlag = 00000002
	O_CREAT     OpenFlag = 00000100
	O_EXCL      OpenFlag = 00000200
	O_NOCTTY    OpenFlag = 00000400
	O_TRUNC     OpenFlag = 00001000
	O_APPEND    OpenFlag = 00002000
	O_NONBLOCK  OpenFlag = 00004000
	O_DSYNC     OpenFlag = 00010000
	O_SYNC      OpenFlag = 04010000
	O_ASYNC     OpenFlag = 020000
	FASYNC      OpenFlag = 00020000
	O_DIRECT    OpenFlag = 00040000
	O_LARGEFILE OpenFlag = 00100000
	O_DIRECTORY OpenFlag = 00200000
	O_NOFOLLOW  OpenFlag = 00400000
	O_NOATIME   OpenFlag = 01000000
	O_CLOEXEC   OpenFlag = 02000000
	O_PATH      OpenFlag = 040000000
	O_TMPFILE   OpenFlag = 020000000
)

// CloneFlagsContains returns true if the passed Clone flag is
// present in cloneArgs which is the raw value passed to the clone
// syscall.
//
// See clone(2) and uapi/linux/sched.h for more information.
func CloneFlagsContains(cloneArgs uint64, flag CloneFlag) bool {
	return cloneFlagsContains(cloneArgs, flag)
}

func cloneFlagsContains(cloneArgs uint64, flag CloneFlag) bool {
	return CloneFlag(cloneArgs)&flag == flag
}

// OpenFlagsContains returns true if the passed Open flag is
// present in openArgs which is the raw value passed to the open
// syscall.
//
// See open(2) and uapi/asm-generic/fcntl.h for more information.
func OpenFlagsContains(openArgs uint32, flag OpenFlag) bool {
	return openFlagsContains(openArgs, flag)
}

func openFlagsContains(openArgs uint32, flag OpenFlag) bool {
	return OpenFlag(openArgs)&flag == flag
}

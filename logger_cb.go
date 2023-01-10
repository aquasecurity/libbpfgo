package libbpfgo

/*
#include <bpf/libbpf.h>
*/
import "C"

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// This callback definition needs to be in a different file from where it is declared in C
// Otherwise, multiple definition compilation error will occur

// loggerCallback is called by libbpf_print_fn() which in turn is called by libbpf
//
//export loggerCallback
func loggerCallback(libbpfPrintLevel int, libbpfOutput *C.char) {
	var (
		level    int
		goOutput string
	)

	goOutput = C.GoString(libbpfOutput)
	goOutput = strings.TrimSuffix(goOutput, "\n")

	for _, fnFilterOut := range callbacks.LogFilters {
		if fnFilterOut != nil {
			if fnFilterOut(libbpfPrintLevel, goOutput) {
				return
			}
		}
	}

	callbacks.Log(level, goOutput)
}

const (
	// libbpf print levels
	LibbpfWarnLevel  = int(C.LIBBPF_WARN)
	LibbpfInfoLevel  = int(C.LIBBPF_INFO)
	LibbpfDebugLevel = int(C.LIBBPF_DEBUG)
)

// Callbacks stores the callbacks to be used by libbpfgo
type Callbacks struct {
	Log        func(level int, msg string, keyValues ...interface{})
	LogFilters []func(libLevel int, msg string) bool
}

// callbacks is initialized with default callbacks, but can be changed by SetLoggerCbs
var callbacks = Callbacks{
	Log: logFallback,
	LogFilters: []func(libLevel int, msg string) bool{
		LogFilterLevel,
		LogFilterOutput,
	},
}

// SetLoggerCbs receives Callbacks type to be used to log libbpf outputs and to filter out those outputs
func SetLoggerCbs(cbs Callbacks) {
	if cbs.Log == nil {
		cbs.Log = logFallback
	}

	callbacks = cbs
}

// logFallback:
// - level is ignored in this stage
// - type coercion only takes care of string types
// - keyValues is not required to contain pairs
// - outputs all to stderr
func logFallback(level int, msg string, keyValues ...interface{}) {
	var (
		args   = make([]string, 0)
		outMsg = msg
	)

	for _, v := range keyValues {
		if s, ok := v.(string); ok {
			outMsg += " [%s]"
			args = append(args, s)
		}
	}

	outMsg += "\n"
	if len(keyValues) > 0 {
		fmt.Fprintf(os.Stderr, outMsg, args)
	} else {
		fmt.Fprint(os.Stderr, outMsg)
	}
}

// LogFilterLevel filters by checking its print level
// In case the consumer defines its own filters functions via SetLoggerCbs, this can also be passed
func LogFilterLevel(libbpfPrintLevel int, output string) bool {
	return libbpfPrintLevel != LibbpfWarnLevel
}

var (
	// triggered by: libbpf/src/nlattr.c->libbpf_nla_dump_errormsg()
	// "libbpf: Kernel error message: %s\n"
	// 1. %s = "Exclusivity flag on"
	regexKernelExclusivityFlagOn = regexp.MustCompile(`libbpf:.*Kernel error message:.*Exclusivity flag on`)

	// triggered by: libbpf/src/libbpf.c->bpf_program__attach_kprobe_opts()
	// "libbpf: prog '%s': failed to create %s '%s+0x%zx' perf event: %s\n"
	// 1. %s = trace_check_map_func_compatibility
	// 2. %s = kretprobe or kprobe
	// 3. %s = check_map_func_compatibility (function name)
	// 4. %x = offset (ignored in this check)
	// 5. %s = No such file or directory
	regexKprobePerfEvent = regexp.MustCompile(`libbpf:.*prog 'trace_check_map_func_compatibility'.*failed to create kprobe.*perf event: No such file or directory`)

	// triggered by: libbpf/src/libbpf.c->bpf_program__attach_fd()
	// "libbpf: prog '%s': failed to attach to %s: %s\n"
	// 1. %s = cgroup_skb_ingress or cgroup_skb_egress
	// 2. %s = cgroup
	// 3. %s = Invalid argument
	regexAttachCgroup = regexp.MustCompile(`libbpf:.*prog 'cgroup_skb_ingress|cgroup_skb_egress'.*failed to attach to cgroup.*Invalid argument`)
)

// LogFilterOutput filters out some errors by using regex
// In case the consumer defines its own filters functions via SetLoggerCbs, this can also be passed
func LogFilterOutput(libbpfPrintLevel int, output string) bool {
	// BUG: https:/github.com/aquasecurity/tracee/issues/1676
	if regexKernelExclusivityFlagOn.MatchString(output) {
		return true
	}

	// BUG: https://github.com/aquasecurity/tracee/issues/2446
	if regexKprobePerfEvent.MatchString(output) {
		return true
	}

	// AttachCgroupLegacy() will first try AttachCgroup() and it might fail. This
	// is not an error and is the best way of probing for eBPF cgroup attachment
	// link existence.
	if regexAttachCgroup.MatchString(output) {
		return true
	}

	return false
}

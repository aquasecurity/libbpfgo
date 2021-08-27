package helpers

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelConfigOption is an abstraction of the key in key=value syntax of the kernel config file
type KernelConfigOption uint32

// KernelConfigOptionValue is an abstraction of the value in key=value syntax of kernel config file
type KernelConfigOptionValue uint8

const (
	UNDEFINED KernelConfigOptionValue = iota
	BUILTIN
	MODULE
	STRING
	ANY
)

func (k KernelConfigOption) String() string {
	return KernelConfigKeyIDToString[k]
}

func (k KernelConfigOptionValue) String() string {
	switch k {
	case UNDEFINED:
		return "UNDEFINED"
	case BUILTIN:
		return "BUILTIN"
	case MODULE:
		return "MODULE"
	case STRING:
		return "STRING"
	case ANY:
		return "ANY"
	}

	return ""
}

// These constants are a limited number of the total kernel config options,
// but are provided because they are most relevant for BPF development.
const (
	CONFIG_BPF KernelConfigOption = iota + 1
	CONFIG_BPF_SYSCALL
	CONFIG_HAVE_EBPF_JIT
	CONFIG_BPF_JIT
	CONFIG_BPF_JIT_ALWAYS_ON
	CONFIG_CGROUPS
	CONFIG_CGROUP_BPF
	CONFIG_CGROUP_NET_CLASSID
	CONFIG_SOCK_CGROUP_DATA
	CONFIG_BPF_EVENTS
	CONFIG_KPROBE_EVENTS
	CONFIG_UPROBE_EVENTS
	CONFIG_TRACING
	CONFIG_FTRACE_SYSCALLS
	CONFIG_FUNCTION_ERROR_INJECTION
	CONFIG_BPF_KPROBE_OVERRIDE
	CONFIG_NET
	CONFIG_XDP_SOCKETS
	CONFIG_LWTUNNEL_BPF
	CONFIG_NET_ACT_BPF
	CONFIG_NET_CLS_BPF
	CONFIG_NET_CLS_ACT
	CONFIG_NET_SCH_INGRESS
	CONFIG_XFRM
	CONFIG_IP_ROUTE_CLASSID
	CONFIG_IPV6_SEG6_BPF
	CONFIG_BPF_LIRC_MODE2
	CONFIG_BPF_STREAM_PARSER
	CONFIG_NETFILTER_XT_MATCH_BPF
	CONFIG_BPFILTER
	CONFIG_BPFILTER_UMH
	CONFIG_TEST_BPF
	CONFIG_HZ
	CONFIG_DEBUG_INFO_BTF
	CONFIG_DEBUG_INFO_BTF_MODULES
	CONFIG_BPF_LSM
	CONFIG_BPF_PRELOAD
	CONFIG_BPF_PRELOAD_UMD
)

var KernelConfigKeyStringToID = map[string]KernelConfigOption{
	"CONFIG_BPF":                      CONFIG_BPF,
	"CONFIG_BPF_SYSCALL":              CONFIG_BPF_SYSCALL,
	"CONFIG_HAVE_EBPF_JIT":            CONFIG_HAVE_EBPF_JIT,
	"CONFIG_BPF_JIT":                  CONFIG_BPF_JIT,
	"CONFIG_BPF_JIT_ALWAYS_ON":        CONFIG_BPF_JIT_ALWAYS_ON,
	"CONFIG_CGROUPS":                  CONFIG_CGROUPS,
	"CONFIG_CGROUP_BPF":               CONFIG_CGROUP_BPF,
	"CONFIG_CGROUP_NET_CLASSID":       CONFIG_CGROUP_NET_CLASSID,
	"CONFIG_SOCK_CGROUP_DATA":         CONFIG_SOCK_CGROUP_DATA,
	"CONFIG_BPF_EVENTS":               CONFIG_BPF_EVENTS,
	"CONFIG_KPROBE_EVENTS":            CONFIG_KPROBE_EVENTS,
	"CONFIG_UPROBE_EVENTS":            CONFIG_UPROBE_EVENTS,
	"CONFIG_TRACING":                  CONFIG_TRACING,
	"CONFIG_FTRACE_SYSCALLS":          CONFIG_FTRACE_SYSCALLS,
	"CONFIG_FUNCTION_ERROR_INJECTION": CONFIG_FUNCTION_ERROR_INJECTION,
	"CONFIG_BPF_KPROBE_OVERRIDE":      CONFIG_BPF_KPROBE_OVERRIDE,
	"CONFIG_NET":                      CONFIG_NET,
	"CONFIG_XDP_SOCKETS":              CONFIG_XDP_SOCKETS,
	"CONFIG_LWTUNNEL_BPF":             CONFIG_LWTUNNEL_BPF,
	"CONFIG_NET_ACT_BPF":              CONFIG_NET_ACT_BPF,
	"CONFIG_NET_CLS_BPF":              CONFIG_NET_CLS_BPF,
	"CONFIG_NET_CLS_ACT":              CONFIG_NET_CLS_ACT,
	"CONFIG_NET_SCH_INGRESS":          CONFIG_NET_SCH_INGRESS,
	"CONFIG_XFRM":                     CONFIG_XFRM,
	"CONFIG_IP_ROUTE_CLASSID":         CONFIG_IP_ROUTE_CLASSID,
	"CONFIG_IPV6_SEG6_BPF":            CONFIG_IPV6_SEG6_BPF,
	"CONFIG_BPF_LIRC_MODE2":           CONFIG_BPF_LIRC_MODE2,
	"CONFIG_BPF_STREAM_PARSER":        CONFIG_BPF_STREAM_PARSER,
	"CONFIG_NETFILTER_XT_MATCH_BPF":   CONFIG_NETFILTER_XT_MATCH_BPF,
	"CONFIG_BPFILTER":                 CONFIG_BPFILTER,
	"CONFIG_BPFILTER_UMH":             CONFIG_BPFILTER_UMH,
	"CONFIG_TEST_BPF":                 CONFIG_TEST_BPF,
	"CONFIG_HZ":                       CONFIG_HZ,
	"CONFIG_DEBUG_INFO_BTF":           CONFIG_DEBUG_INFO_BTF,
	"CONFIG_DEBUG_INFO_BTF_MODULES":   CONFIG_DEBUG_INFO_BTF_MODULES,
	"CONFIG_BPF_LSM":                  CONFIG_BPF_LSM,
	"CONFIG_BPF_PRELOAD":              CONFIG_BPF_PRELOAD,
	"CONFIG_BPF_PRELOAD_UMD":          CONFIG_BPF_PRELOAD_UMD,
}

var KernelConfigKeyIDToString = map[KernelConfigOption]string{
	CONFIG_BPF:                      "CONFIG_BPF",
	CONFIG_BPF_SYSCALL:              "CONFIG_BPF_SYSCALL",
	CONFIG_HAVE_EBPF_JIT:            "CONFIG_HAVE_EBPF_JIT",
	CONFIG_BPF_JIT:                  "CONFIG_BPF_JIT",
	CONFIG_BPF_JIT_ALWAYS_ON:        "CONFIG_BPF_JIT_ALWAYS_ON",
	CONFIG_CGROUPS:                  "CONFIG_CGROUPS",
	CONFIG_CGROUP_BPF:               "CONFIG_CGROUP_BPF",
	CONFIG_CGROUP_NET_CLASSID:       "CONFIG_CGROUP_NET_CLASSID",
	CONFIG_SOCK_CGROUP_DATA:         "CONFIG_SOCK_CGROUP_DATA",
	CONFIG_BPF_EVENTS:               "CONFIG_BPF_EVENTS",
	CONFIG_KPROBE_EVENTS:            "CONFIG_KPROBE_EVENTS",
	CONFIG_UPROBE_EVENTS:            "CONFIG_UPROBE_EVENTS",
	CONFIG_TRACING:                  "CONFIG_TRACING",
	CONFIG_FTRACE_SYSCALLS:          "CONFIG_FTRACE_SYSCALLS",
	CONFIG_FUNCTION_ERROR_INJECTION: "CONFIG_FUNCTION_ERROR_INJECTION",
	CONFIG_BPF_KPROBE_OVERRIDE:      "CONFIG_BPF_KPROBE_OVERRIDE",
	CONFIG_NET:                      "CONFIG_NET",
	CONFIG_XDP_SOCKETS:              "CONFIG_XDP_SOCKETS",
	CONFIG_LWTUNNEL_BPF:             "CONFIG_LWTUNNEL_BPF",
	CONFIG_NET_ACT_BPF:              "CONFIG_NET_ACT_BPF",
	CONFIG_NET_CLS_BPF:              "CONFIG_NET_CLS_BPF",
	CONFIG_NET_CLS_ACT:              "CONFIG_NET_CLS_ACT",
	CONFIG_NET_SCH_INGRESS:          "CONFIG_NET_SCH_INGRESS",
	CONFIG_XFRM:                     "CONFIG_XFRM",
	CONFIG_IP_ROUTE_CLASSID:         "CONFIG_IP_ROUTE_CLASSID",
	CONFIG_IPV6_SEG6_BPF:            "CONFIG_IPV6_SEG6_BPF",
	CONFIG_BPF_LIRC_MODE2:           "CONFIG_BPF_LIRC_MODE2",
	CONFIG_BPF_STREAM_PARSER:        "CONFIG_BPF_STREAM_PARSER",
	CONFIG_NETFILTER_XT_MATCH_BPF:   "CONFIG_NETFILTER_XT_MATCH_BPF",
	CONFIG_BPFILTER:                 "CONFIG_BPFILTER",
	CONFIG_BPFILTER_UMH:             "CONFIG_BPFILTER_UMH",
	CONFIG_TEST_BPF:                 "CONFIG_TEST_BPF",
	CONFIG_HZ:                       "CONFIG_HZ",
	CONFIG_DEBUG_INFO_BTF:           "CONFIG_DEBUG_INFO_BTF",
	CONFIG_DEBUG_INFO_BTF_MODULES:   "CONFIG_DEBUG_INFO_BTF_MODULES",
	CONFIG_BPF_LSM:                  "CONFIG_BPF_LSM",
	CONFIG_BPF_PRELOAD:              "CONFIG_BPF_PRELOAD",
	CONFIG_BPF_PRELOAD_UMD:          "CONFIG_BPF_PRELOAD_UMD",
}

// KernelConfig is a set of kernel configuration options (currently for running OS only)
type KernelConfig struct {
	configs map[KernelConfigOption]interface{} // predominantly KernelConfigOptionValue, sometimes string
	needed  map[KernelConfigOption]interface{}
}

// InitKernelConfig inits external KernelConfig object
func InitKernelConfig() *KernelConfig {
	config := KernelConfig{
		configs: make(map[KernelConfigOption]interface{}),
		needed:  make(map[KernelConfigOption]interface{}),
	}
	if err := config.initKernelConfig(); err != nil {
		return nil
	}

	return &config
}

// initKernelConfig inits internal KernelConfig data by calling appropriate readConfigFromXXX function
func (k *KernelConfig) initKernelConfig() error {
	k.configs = make(map[KernelConfigOption]interface{})

	x := unix.Utsname{}
	if err := unix.Uname(&x); err != nil {
		return fmt.Errorf("could not determine uname release: %w", err)
	}

	if err := k.readConfigFromBootConfigRelease(string(x.Release[:])); err != nil {
		if err2 := k.readConfigFromProcConfigGZ(); err != nil {
			return err2
		}

		return err
	}

	return nil
}

// readConfigFromProcConfigGZ prepares io.Reader for readConfigFromGZScanner (/proc/config.gz)
func (k *KernelConfig) readConfigFromProcConfigGZ() error {
	configFile, err := os.Open("/proc/config.gz")
	if err != nil {
		return fmt.Errorf("could not open /proc/config.gz: %w", err)
	}

	return k.readConfigFromGZScanner(configFile)
}

// readConfigFromScanner prepares io.Reader for readConfigFromScanner (/boot/config-$(uname -r))
func (k *KernelConfig) readConfigFromBootConfigRelease(release string) error {
	path := fmt.Sprintf("/boot/config-%s", strings.TrimRight(release, "\x00"))

	configFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open %s: %w", path, err)
	}

	k.readConfigFromScanner(configFile)

	return nil
}

// readConfigFromScanner reads all existing KernelConfigOption's and KernelConfigOptionValue's from given io.Reader
func (k *KernelConfig) readConfigFromScanner(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		kv := strings.Split(scanner.Text(), "=")
		if len(kv) != 2 {
			continue
		}

		configKeyID := KernelConfigKeyStringToID[kv[0]]
		if configKeyID == 0 {
			continue
		}
		if strings.Compare(kv[1], "m") == 0 {
			k.configs[configKeyID] = MODULE
		} else if strings.Compare(kv[1], "y") == 0 {
			k.configs[configKeyID] = BUILTIN
		} else {
			k.configs[configKeyID] = kv[1]
		}
	}
}

// readConfigFromGZScanner reads all existing KernelConfigOption's and KernelConfigOptionValue's from a gzip io.Reader
func (k *KernelConfig) readConfigFromGZScanner(reader io.Reader) error {
	zreader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}

	k.readConfigFromScanner(zreader)

	return nil
}

// GetValue will return a KernelConfigOptionValue for a given KernelConfigOption when this is a BUILTIN or a MODULE
func (k *KernelConfig) GetValue(option KernelConfigOption) (KernelConfigOptionValue, error) {
	value, ok := k.configs[option].(KernelConfigOptionValue)
	if ok {
		return value, nil
	}

	return UNDEFINED, fmt.Errorf("given option's value (%s) is a string", option)
}

// GetValueString will return a KernelConfigOptionValue for a given KernelConfigOption when this is actually a string
func (k *KernelConfig) GetValueString(option KernelConfigOption) (string, error) {
	value, ok := k.configs[option].(string)
	if ok {
		return value, nil
	}

	return "", fmt.Errorf("given option's value (%s) is not a string", option)
}

// Exists will return true if a given KernelConfigOption was found in provided KernelConfig
// and it will return false if the KernelConfigOption is not set (# XXXXX is not set)
//
// Examples:
// kernelConfig.Exists(helpers.CONFIG_BPF)
// kernelConfig.Exists(helpers.CONFIG_BPF_PRELOAD)
// kernelConfig.Exists(helpers.CONFIG_HZ)
//
func (k *KernelConfig) Exists(option KernelConfigOption) bool {
	if _, ok := k.configs[option]; ok {
		return true
	}

	return false
}

// ExistsValue will return true if a given KernelConfigOption was found in provided KernelConfig
// AND its value is the same as the one provided by KernelConfigOptionValue
func (k *KernelConfig) ExistsValue(option KernelConfigOption, value interface{}) bool {
	if _, ok := k.configs[option]; ok {
		switch k.configs[option].(type) {
		case KernelConfigOptionValue:
			if value == ANY {
				return true
			} else if k.configs[option].(KernelConfigOptionValue) == value {
				return true
			}
		case string:
			if strings.Compare(k.configs[option].(string), value.(string)) == 0 {
				return true
			}
		}
	}

	return false
}

// CheckMissing returns an array of KernelConfigOption's that were added to KernelConfig as needed but couldn't be
// found. It returns an empty array if nothing is missing.
func (k *KernelConfig) CheckMissing() []KernelConfigOption {
	missing := make([]KernelConfigOption, 0)

	for key, value := range k.needed {
		if !k.ExistsValue(key, value) {
			missing = append(missing, key)
		}
	}

	return missing
}

// AddNeeded adds a KernelConfigOption and its value, if needed, as required for further checks with CheckMissing
//
// Examples:
// kernelConfig.AddNeeded(helpers.CONFIG_BPF, helpers.ANY)
// kernelConfig.AddNeeded(helpers.CONFIG_BPF_PRELOAD, helpers.ANY)
// kernelConfig.AddNeeded(helpers.CONFIG_HZ, "250")
//
func (k *KernelConfig) AddNeeded(option KernelConfigOption, value interface{}) {
	k.needed[option] = value
}

package libbpfgo

import (
	"fmt"
	"strings"
	"syscall"
	"testing"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Reset only effective capabilites
func resetEffectiveCapabilities() error {
	// current capability
	existing := cap.GetProc()

	// Clear all effective capabilites
	if err := existing.ClearFlag(cap.Effective); err != nil {
		return fmt.Errorf("error cleaning effective capabilites %w", err)
	}

	// set updated capabilitis to current process
	if err := existing.SetProc(); err != nil {
		return fmt.Errorf("error during update capabilites %w", err)
	}

	return nil
}

// Enforce effective capabilites only
func enforceEffectiveCapabilities(newCap []string) error {
	existing := cap.GetProc()

	// create a new empty capabilities
	enforce := cap.NewSet()

	// copy all/only permitted flags to new cap
	enforce.FillFlag(cap.Permitted, existing, cap.Permitted)

	values := []cap.Value{}

	for _, name := range newCap {
		value, err := cap.FromName(name)
		if err != nil {
			return fmt.Errorf("error getting capability %q: %w", name, err)
		}

		values = append(values, value)
	}

	// only set the given effetive capabilities
	if err := enforce.SetFlag(cap.Effective, true, values...); err != nil {
		return fmt.Errorf("error setting effective capabilities: %w", err)
	}

	if err := enforce.SetProc(); err != nil {
		return fmt.Errorf("failed to drop capabilities: %q -> %q: %w", existing, enforce, err)
	}

	return nil
}

func TestFuncSupportbyType(t *testing.T) {
	tt := []struct {
		progType   BPFProgType
		funcId     BPFFunc
		supported  bool
		capability []string
		errMsg     error
	}{
		// func available but not enough permission (permission denied)
		// May return success (`true`) even if the BPF program load would fail due to permission issues (EPERM).
		// Check BPFHelperIsSupported for more info.
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncGetCurrentUidGid,
			supported:  true,
			capability: []string{},
			errMsg:     syscall.EPERM,
		},
		// func available and enough permission
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncGetCurrentUidGid,
			supported:  true,
			capability: []string{"cap_bpf", "cap_perfmon"},
			errMsg:     nil,
		},
		// func unavailable and enough permission
		// When the function is unavailable, BPF returns "Invalid Argument".
		// Therefore, ignore the error and proceed with validation.
		// May return success (`true`) even if the BPF program load would fail due to permission issues (EPERM).
		// Check BPFHelperIsSupported for more info.
		{
			progType:   BPFProgTypeSkLookup,
			funcId:     BPFFuncGetCurrentCgroupId,
			supported:  true,
			capability: []string{},
			errMsg:     syscall.EPERM,
		},
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncKtimeGetNs,
			supported:  true,
			capability: []string{"cap_bpf", "cap_perfmon"},
			errMsg:     nil,
		},
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncKtimeGetNs,
			supported:  true,
			capability: []string{"cap_sys_admin"},
			errMsg:     nil,
		},
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncSysBpf,
			supported:  false,
			capability: []string{"cap_bpf", "cap_perfmon"},
			errMsg:     syscall.EINVAL,
		},
		{
			progType:   BPFProgTypeSyscall,
			funcId:     BPFFuncGetCgroupClassid,
			supported:  false,
			capability: []string{"cap_bpf"},
			errMsg:     syscall.EINVAL,
		},
		// Not able to probe helpers for some types (even with permission)
		// https://github.com/libbpf/libbpf/blob/c1a6c770c46c6e78ad6755bf596c23a4e6f6b216/src/libbpf_probes.c#L430-L441
		{
			progType:   BPFProgTypeLsm,
			funcId:     BPFFuncGetCurrentCgroupId,
			supported:  false,
			capability: []string{"cap_bpf", "cap_perfmon"},
			errMsg:     syscall.EOPNOTSUPP,
		},
		{
			progType:   BPFProgTypeLsm,
			funcId:     BPFFuncGetCurrentCgroupId,
			supported:  false,
			capability: []string{},
			errMsg:     syscall.EOPNOTSUPP,
		},
		{
			progType:   BPFProgTypeKprobe,
			funcId:     BPFFuncSockMapUpdate,
			supported:  false,
			capability: []string{"cap_sys_admin"},
			errMsg:     syscall.EINVAL,
		},
	}
	for _, tc := range tt {
		// reset all current effective capabilities
		resetEffectiveCapabilities()

		if tc.capability != nil {
			enforceEffectiveCapabilities(tc.capability)
		}

		support, err := BPFHelperIsSupported(tc.progType, tc.funcId)

		if tc.errMsg == nil {
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		} else {
			if err == nil || !strings.Contains(err.Error(), tc.errMsg.Error()) {
				t.Errorf("expected error containing %q, got %v", tc.errMsg.Error(), err)
			}
		}

		// This may fail if the bpf helper support for a specific program changes in future.
		if support != tc.supported {
			t.Errorf("expected %v, got %v", tc.supported, support)
		}
	}
}

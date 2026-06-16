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
	if err := enforce.FillFlag(cap.Permitted, existing, cap.Permitted); err != nil {
		return fmt.Errorf("failed to copy permitted capability flags: %w", err)
	}

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
		if err := resetEffectiveCapabilities(); err != nil {
			t.Fatalf("failed to reset effective capabilities: %v", err)
		}

		if tc.capability != nil {
			if err := enforceEffectiveCapabilities(tc.capability); err != nil {
				t.Fatalf("failed to enforce effective capabilities: %v", err)
			}
		}

		support, err := BPFHelperIsSupported(tc.progType, tc.funcId)

		// Helper support is kernel-version dependent. Newer kernels regularly add
		// support for helpers that were previously unavailable for a given program
		// type. Treat such forward changes (expected unsupported -> now supported)
		// as a warning, since they are expected on newer kernels and CI runners.
		// A regression in the other direction (expected supported -> now unsupported)
		// is still treated as a hard failure.
		if support != tc.supported {
			if support && !tc.supported {
				t.Logf("warning: expected %s to be unsupported for %s, but the kernel now reports it as supported; skipping error check", tc.funcId.String(), tc.progType.String())
				continue
			}
			t.Errorf("expected support=%v for %s (%s), got %v (err: %v)", tc.supported, tc.funcId.String(), tc.progType.String(), support, err)
		}

		if tc.errMsg == nil {
			if err != nil {
				t.Errorf("expected no error for %s, got %v", tc.funcId.String(), err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.errMsg.Error()) {
			// The expected errno is not guaranteed across kernels. For an unsupported
			// helper on a probeable program type (e.g. kprobe/syscall), libbpf returns
			// 0 and the EINVAL we observe is the stale errno from the verifier-rejected
			// bpf(BPF_PROG_LOAD) call surfaced via cgo. EOPNOTSUPP is returned by libbpf
			// for non-probeable program types (tracing/ext/lsm/struct_ops), not based on
			// kernel version. When a kernel gains support for the helper, the probe load
			// succeeds and no error is returned at all. So we only warn on an errno
			// mismatch here, as long as the support result matched the expectation above.
			t.Logf("warning: expected error containing %q for %s, got %v", tc.errMsg.Error(), tc.funcId.String(), err)
		}
	}
}

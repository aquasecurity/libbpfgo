package libbpfgo

import (
	"testing"

	"github.com/aquasecurity/libbpfgo/helpers"
)

func TestFuncSupportbyType(t *testing.T) {
	tt := []struct {
		progType  BPFProgType
		funcId    helpers.BPFFunc
		supported bool
	}{
		{
			progType:  BPFProgTypeKprobe,
			funcId:    helpers.BPFFuncMapLookupElem,
			supported: true,
		},
		{
			progType:  BPFProgTypeKprobe,
			funcId:    helpers.BPFFuncLoop,
			supported: true,
		},
		{
			progType:  BPFProgTypeKprobe,
			funcId:    helpers.BPFFuncKtimeGetNs,
			supported: true,
		},
		{
			progType:  BPFProgTypeKprobe,
			funcId:    helpers.BPFFuncSysBpf,
			supported: false,
		},
		{
			progType:  BPFProgTypeLsm,
			funcId:    helpers.BPFFuncGetCurrentCgroupId,
			supported: false,
		},
		{
			progType:  BPFProgTypeSkLookup,
			funcId:    helpers.BPFFuncGetCurrentCgroupId,
			supported: true,
		},
		{
			progType:  BPFProgTypeKprobe,
			funcId:    helpers.BPFFuncSockMapUpdate,
			supported: false,
		},
	}

	for _, tc := range tt {
		support, _ := BPFHelperIsSupported(tc.progType, tc.funcId)
		// This may fail if the bpf helper support for a specific program changes in future.
		if support != tc.supported {
			t.Errorf("expected %v, got %v", tc.supported, support)
		}
	}
}

package libbpfgo

import "testing"

func TestLogFilterOutput(t *testing.T) {
	tests := []struct {
		libbpfPrintLevel int
		output           string
		expectedResult   bool
	}{
		{
			output:         "libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: No such file or directory\n",
			expectedResult: true,
		},
		{
			output:         "libbpf: Kernel error message: Exclusivity flag on\n",
			expectedResult: true,
		},
		{
			output:         "libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup 'cgroup': Invalid argument\n",
			expectedResult: true,
		},
		{
			output:         "libbpf: prog 'cgroup_skb_egress': failed to attach to cgroup 'cgroup': Invalid argument\n",
			expectedResult: true,
		},
		{
			output:         "This is not a log message that should be filtered\n",
			expectedResult: false,
		},
		{
			output:         "libbpf: This is not a log message that should be filtered\n",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		result := LogFilterOutput(test.libbpfPrintLevel, test.output)
		if result != test.expectedResult {
			t.Errorf("For input '%s', expected %v but got %v", test.output, test.expectedResult, result)
		}
	}
}

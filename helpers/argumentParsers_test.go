package helpers

import (
	"testing"

	"github.com/aquasecurity/libbpfgo"
	"github.com/stretchr/testify/assert"
)

func TestOptionsContainedInArgument(t *testing.T) {

	attachTests := []struct {
		testName          string
		rawArgument       uint64
		options           []SystemFunctionArgument
		expectedContained bool
		expectedValue     uint64
		expectedString    string
	}{
		{
			testName:          "no options present",
			rawArgument:       0x0,
			options:           []SystemFunctionArgument{CLONE_CHILD_CLEARTID},
			expectedContained: false,
		},
		{
			testName:          "present in self",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "present in self multiple",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "just not present",
			rawArgument:       PTRACE_PEEKTEXT.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "present1",
			rawArgument:       PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_GETSIGMASK},
			expectedContained: true,
		},
		{
			testName:          "present2",
			rawArgument:       BPF_MAP_CREATE.Value(),
			options:           []SystemFunctionArgument{BPF_MAP_CREATE},
			expectedContained: true,
		},
		{
			testName:          "present3",
			rawArgument:       CAP_CHOWN.Value(),
			options:           []SystemFunctionArgument{CAP_CHOWN},
			expectedContained: true,
		},
	}

	for _, ts := range attachTests {
		t.Run(ts.testName, func(test *testing.T) {
			isContained := OptionAreContainedInArgument(ts.rawArgument, ts.options...)
			assert.Equal(test, ts.expectedContained, isContained)
		})
	}
}

func TestParseSetSocketOption(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Normal value",
			parseValue:    SO_DEBUG.Value(),
			expectedSting: "SO_DEBUG",
			expectedError: false,
		},
		{
			name:          "Get changed value",
			parseValue:    SO_ATTACH_FILTER.Value(),
			expectedSting: "SO_ATTACH_FILTER",
			expectedError: false,
		},
		{
			name:          "Non existing value",
			parseValue:    10000000,
			expectedSting: "",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseSetSocketOption(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

func TestParseGetSocketOption(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Normal value",
			parseValue:    SO_DEBUG.Value(),
			expectedSting: "SO_DEBUG",
			expectedError: false,
		},
		{
			name:          "Get changed value",
			parseValue:    SO_GET_FILTER.Value(),
			expectedSting: "SO_GET_FILTER",
			expectedError: false,
		},
		{
			name:          "Non existing value",
			parseValue:    10000000,
			expectedSting: "",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseGetSocketOption(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

func TestParseBPFProgType(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Type tracepoint",
			parseValue:    libbpfgo.BPFProgTypeTracepoint.Value(),
			expectedSting: "BPF_PROG_TYPE_TRACEPOINT",
			expectedError: false,
		},
		{
			name:          "Non existing type",
			parseValue:    10000000,
			expectedSting: "BPF_PROG_TYPE_UNSPEC",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseBPFProgType(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

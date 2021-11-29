package helpers

import (
	"testing"

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
	}

	for _, ts := range attachTests {
		t.Run(ts.testName, func(test *testing.T) {
			isContained := OptionAreContainedInArgument(ts.rawArgument, ts.options...)
			assert.Equal(test, ts.expectedContained, isContained)
		})
	}
}

package libbpfgo

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogFallback(t *testing.T) {
	tt := []struct {
		message string
	}{
		{
			message: "This is a warning message",
		},
		{
			message: "This is a information message",
		},
		{
			message: "This is a debug message",
		},
	}

	for _, tc := range tt {
		var buf bytes.Buffer

		r, w, err := os.Pipe()
		require.NoError(t, err, "failed to create pipe")

		writeEnd := os.NewFile(uintptr(w.Fd()), "pipe")

		oldStderr := os.Stderr
		os.Stderr = writeEnd

		// level is ignored
		logFallback(LibbpfInfoLevel, tc.message)

		os.Stderr = oldStderr

		err = writeEnd.Close()
		require.NoError(t, err, "failed to close writeEnd")
		_, err = io.Copy(&buf, r)
		require.NoError(t, err, "failed to copy from read end to buffer")

		assert.Equal(t, tc.message, buf.String())
	}
}

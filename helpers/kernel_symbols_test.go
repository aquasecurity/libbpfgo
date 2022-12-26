package helpers

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run tests as such
// alias mysudo='sudo -E env "PATH=$PATH"'
// cd helpers
// mysudo go test
func TestKernelSymbols(t *testing.T) {
	const (
		owner  = "system"
		symbol = "do_sys_openat2"
	)
	syms, err := NewKernelSymbolsMap()
	require.NoError(t, err)
	lSyms, err := NewLazyKernelSymbolsMap()
	require.NoError(t, err)
	res, err1 := syms.GetSymbolByName(owner, symbol)
	res2, err2 := lSyms.GetSymbolByName(owner, symbol)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, res, res2)
	addr := res.Address
	res, err1 = syms.GetSymbolByAddr(addr)
	res2, err2 = lSyms.GetSymbolByAddr(addr)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, res, res2)
}

// run benchmarks as such
// alias mysudo='sudo -E env "PATH=$PATH"'
// cd helpers
// mysudo go test -bench=.

const (
	max   = 812435456
	start = 0xffffffff90000000
	end   = 0xffffffffc06cc738
)

func BenchmarkLazySymByAddr(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	seed := uint64(rand.Intn(max))
	addr := seed + uint64(start)
	syms, err := NewLazyKernelSymbolsMap()
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		syms.GetSymbolByAddr(addr)
	}
}

func BenchmarkLazySymByAddrNotBinary(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	seed := uint64(rand.Intn(max))
	addr := seed + uint64(start)
	syms, err := NewLazyKernelSymbolsMap()
	lSyms := syms.(*lazyKernelSymbols)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		lSyms.getSymbolByAddrNotBinary(addr)
	}
}

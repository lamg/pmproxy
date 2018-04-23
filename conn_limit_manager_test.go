package pmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCLMng(t *testing.T) {
	lim := uint32(100)
	cl := NewCLMng("test", lim)
	ip := "10.1.1.1"
	for i := uint32(0); i != 2*lim; i++ {
		ok := cl.AddConn(ip)
		require.Equal(t, ok, i <= lim, "At %d", i)
		n := cl.GetAmount(ip)
		if ok {
			require.Equal(t, i, n)
		} else {
			require.Equal(t, lim, n)
		}
	}
	cl.DecreaseAm(ip)
	n := cl.GetAmount(ip)
	require.Equal(t, lim-1, n)
}

package pmproxy

import (
	"fmt"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestCLMng(t *testing.T) {
	lim := uint32(100)
	cl := NewCLMng("test", lim)
	ip := "10.1.1.1"
	for i := uint32(0); i != 2*lim; i++ {
		ok := cl.AddConn(ip)
		require.Equal(t, ok, i <= lim, "At %d", i)
		n := cl.Amount(ip)
		if ok {
			require.Equal(t, i, n)
		} else {
			require.Equal(t, lim, n)
		}
	}
	cl.DecreaseAm(ip)
	n := cl.Amount(ip)
	require.Equal(t, lim-1, n)
}

func TestCLMngHandler(t *testing.T) {
	lim := uint32(100)
	cl := NewCLMng("test", lim)
	p, path := cl.PrefixHandler(), "/"+cl.Name
	w, r := reqres(t, h.MethodGet, path, "", "", "0.0.0.0")
	p.Hnd.ServeHTTP(w, r)
	lims := fmt.Sprintf("%d", cl.Limit)
	require.Equal(t, lims, w.Body.String())
	nlim := uint32(99)
	nlims := fmt.Sprintf("%d", nlim)
	w, r = reqres(t, h.MethodPut, path, nlims, "", "0.0.0.0")
	p.Hnd.ServeHTTP(w, r)
	require.Equal(t, nlim, cl.Limit)
}

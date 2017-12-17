package pmproxy_test

import (
	h "net/http"
	"testing"

	"github.com/stretchr/testify/require"

	pm "github.com/lamg/pmproxy"
)

func TestServeHTTP(t *testing.T) {
	rw, sc := make([]chan *pm.ProxHnd, 1), make(chan bool)
	rw[0] = make(chan *pm.ProxHnd)
	rrw := make([]chan<- *pm.ProxHnd, 1)
	rrw[0] = rw[0]
	prx := &pm.PMProxy{
		Pr:   rrw,
		Stop: sc,
	}
	w, r := reqres(t, h.MethodGet, "", "", "", "")
	go prx.ServeHTTP(w, r)
	ph := <-rw[0]
	require.Equal(t, h.MethodGet, ph.Rq.Method)
	sc <- true
}

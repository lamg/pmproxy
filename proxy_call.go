package pmproxy

import (
	h "net/http"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	proxy h.Handler
}

// ProcMsg processes a message or a request if there is
// no message
func (p *PMProxy) ProcMsg(w h.ResponseWriter, r *h.Request,
	mc <-chan string) {
	m := <-mc
	if m != "" {
		w.Write([]byte(m))
	} else {
		p.proxy.ServeHTTP(w, r)
	}
}

// ServeProxy is the h.HandlerFunc for proxying requests
func (p *PMProxy) ServeProxy(w h.ResponseWriter,
	r *h.Request) {
	mcs := make([]chan string, 1)
	//go SessionFlt(r, mcs[0])
	// { stored channels }
	mc := make(chan string)
	go MultMsg(mcs, mc)
	p.ProcMsg(w, r, mc)
}

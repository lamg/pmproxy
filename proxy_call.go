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

func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	mcs := make([]chan string, 0)
	// { stored channels }
	mc := make(chan string)
	MultMsg(mcs, mc)
	p.ProcMsg(w, r, mc)
}

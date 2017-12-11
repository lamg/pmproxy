package pmproxy

import (
	h "net/http"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	proxy h.Handler
}

type proxReq struct {
	w   h.ResponseWriter
	r   *h.Request
	msg string
}

// ProcMsg processes a message or a request if there is
// no message
func (p *PMProxy) ProcMsg(pr <-chan *proxReq) {
	r := <-pr
	if r.msg != "" {
		r.w.Write([]byte(r.msg))
	} else {
		p.proxy.ServeHTTP(r.w, r.r)
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
	// TODO
}

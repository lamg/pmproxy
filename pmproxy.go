package pmproxy

import (
	h "net/http"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	Pr []MaybeResp
}

// MaybeResp abstracts an h.Handler that may
// respond to an *h.Request
type MaybeResp interface {
	Resp(w h.ResponseWriter, r *h.Request) bool
}

// ServeProxy is the h.HandlerFunc for proxying requests
func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	stop := false
	for i := 0; !stop && i != len(p.Pr); i++ {
		stop = p.Pr[i].Resp(w, r)
	}
}

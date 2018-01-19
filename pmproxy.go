package pmproxy

import (
	h "net/http"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	Pr []MaybeResp
}

type MaybeResp interface {
	Bool
	h.Handler
}

// MaybeResp abstracts an h.Handler that may
// respond to an *h.Request
type mResp struct {
	w h.ResponseWriter
	r *h.Request
	m MaybeResp
}

func (m *mResp) V() (y bool) {
	m.m.ServeHTTP(m.w, m.r)
	y = m.m.V()
	return
}

// ServeProxy is the h.HandlerFunc for proxying requests
func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	mr := make([]Bool, len(p.Pr))
	for i, j := range p.Pr {
		mr[i] = &mResp{w: w, r: r, m: j}
	}
	BoundedLinearSearch(mr)
}

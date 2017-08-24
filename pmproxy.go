package pmproxy

import (
	. "net/http"
)

type PMProxy struct {
	local, remote Handler
}

func (p *PMProxy) Init(local, remote Handler) {
	p.local, p.remote = local, remote
}

func (p *PMProxy) ServeHTTP(w ResponseWriter, r *Request) {
	if r.URL.Host == "" {
		p.local.ServeHTTP(w, r)
	} else {
		p.remote.ServeHTTP(w, r)
	}
}

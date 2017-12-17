package pmproxy

import (
	h "net/http"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	Pr   []chan<- *ProxHnd
	Stop <-chan bool
}

// ProxHnd has the parameters for handling a proxy request
// and response
type ProxHnd struct {
	RW h.ResponseWriter
	Rq *h.Request
}

// ServeProxy is the h.HandlerFunc for proxying requests
func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	stop, ph := false, &ProxHnd{RW: w, Rq: r}
	for i := 0; !stop && i != len(p.Pr); i++ {
		p.Pr[i] <- ph
		stop = <-p.Stop
	}
}

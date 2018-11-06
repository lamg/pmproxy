package pmproxy

import (
	h "net/http"
)

type proxySpec struct {
}

func (p *proxySpec) ServeSpec(s *Spec, w h.ResponseWriter,
	r *h.Request) {
	// TODO API boundary problem
}

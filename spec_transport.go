package pmproxy

import (
	"github.com/lamg/clock"
	"github.com/lamg/proxy"
	h "net/http"
)

type specTransport struct {
	tr    *h.Transport
	rs    *simpleRspec
	clock clock.Clock
}

type specKeyT string

func (p *proxySpec) RoundTripp(r *h.Request) (n *h.Response,
	e error) {
	tm := p.clock.Now()
	var s *Spec
	s, e = p.rs.Spec(tm, r)
	if e == nil {
		ctx := r.Context()
		nctx := context.WithValue(ctx, specKeyT("spec"), s)
		r.WithContext(nctx)
		n, e = p.tr.RoundTrip(r)
	}
	return
}

func (p *proxySpec) DialContext(ctx context.Context, network,
	addr string) (c net.Conn, e error) {
	s := ctx.Value(specKeyT("spec")).(*Spec)

	// TODO dial with s
	return
}

package pmproxy

import (
	"github.com/lamg/clock"
	gp "github.com/lamg/proxy"
	"net"
	h "net/http"
	"time"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	// Resource managers
	Rd      []Det
	Cl      clock.Clock
	Dl      Dialer
	pr      *gp.Proxy
	Timeout time.Duration
	Ifp     IfaceProv
}

func NewPMProxy(rd []Det, cl clock.Clock, d *h.Transport,
	t time.Duration, ifp IfaceProv) (p *PMProxy) {
	proxy := gp.Proxy{
		Tr: d,
	}
	p = &PMProxy{
		Rd:      rd,
		Cl:      cl,
		Dl:      d,
		pr:      proxy,
		Timeout: t,
		Ifp:     ifp,
	}
	return
}

func (p *PMProxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	s, nw := new(ConSpec), p.Cl.Now()
	for i := 0; i != len(p.Rd); i++ {
		p.Rd[i].Det(r, nw, s)
	}
	// get a configured transport according s?

	c, e = connect(addr, s, p.pr, p.Timeout, p.Cl, p.Dl,
		p.Ifp)
}

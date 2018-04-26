package pmproxy

import (
	"github.com/lamg/clock"
	gp "github.com/lamg/goproxy"
	"net"
	"time"
)

// PMProxy does some preprocessing before proxying
type PMProxy struct {
	// Resource managers
	Rd      []Det
	Cl      clock.Clock
	Dl      Dialer
	pr      *gp.ProxyHttpServer
	Timeout time.Duration
	Ifp     IfaceProv
}

func NewPMProxy(rd []Det, cl clock.Clock, d Dialer,
	t time.Duration, ifp IfaceProv) (p *PMProxy) {
	p = &PMProxy{
		Rd:      rd,
		Cl:      cl,
		Dl:      d,
		pr:      gp.NewProxyHttpServer(),
		Timeout: t,
		Ifp:     ifp,
	}
	return
}

// Dial is the entry point for connecting according the
// matching resources
func (p *PMProxy) Dial(ntw, addr string,
	ctx *gp.ProxyCtx) (c net.Conn, e error) {
	s, nw := new(ConSpec), p.Cl.Now()
	for i := 0; i != len(p.Rd); i++ {
		p.Rd[i].Det(ctx.Req, nw, s)
	}
	c, e = connect(addr, s, p.pr, p.Timeout, p.Cl, p.Dl,
		p.Ifp)
	return
}

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
	d       Dialer
	pr      *gp.ProxyHttpServer
	timeout time.Duration
}

// Dial is the entry point for connecting according the 
// matching resources
func (p *PMProxy) Dial(ntw, addr string,
	ctx *gp.ProxyCtx) (c net.Conn, e error) {
	s, nw := new(ConSpec), p.Cl.Now()
	for i := 0; i != len(p.Rd); i++ {
		p.Rd[i].Det(ctx.Req, nw, s)
	}
	c, e = connect(addr, s, p.pr, p.timeout, p.Cl, p.d)
	return
}

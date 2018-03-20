package pmproxy

import (
	"fmt"
	"github.com/juju/ratelimit"
	"github.com/lamg/clock"
	gp "github.com/lamg/goproxy"
	rs "github.com/lamg/rtimespan"
	"io"
	"net"
	"time"
)

// connect returns a connection according with the specifications
// in s
func connect(addr string, s *ConSpec, p *gp.ProxyHttpServer,
	timeout time.Duration, cl clock.Clock, d Dialer) (c net.Conn,
	e error) {
	if !s.Valid() {
		e = fmt.Errorf("La conexión no puede completarse %v", s)
	}
	if e == nil {
		if s.Proxy != "" {
			c, e = proxyConn(p, s.Proxy, addr)
		} else {
			c, e = interfaceConn(s.Iface, addr, timeout, d)
		}
	}
	if e == nil {
		if s.Span != nil {
			c = &rspanConn{
				Conn: c,
				cl:   cl,
				sp:   s.Span,
			}
		}
		if s.Rt != nil {
			c = throttleConn(c, s.Rt)
		}
		if s.Cl != nil && s.Cl.AddConn(addr) {
			c = &limitConn{
				Conn: c,
				l:    s.Cl,
			}
		}
		c = &quotaConn{
			Conn:  c,
			Quota: s.Quota,
			Cons:  s.Cons,
		}
	}
	return
}

type limitConn struct {
	net.Conn
	l *CLMng
}

func (c *limitConn) Close() (e error) {
	c.l.DecreaseAm(c.LocalAddr().String())
	e = c.Close()
	return
}

type thrConn struct {
	net.Conn
	r io.Reader
}

func (c *thrConn) Read(bs []byte) (n int, e error) {
	n, e = c.r.Read(bs)
	return
}

func throttleConn(c net.Conn, r *Rate) (n net.Conn) {
	bk := ratelimit.NewBucket(r.TimeLapse, r.Bytes)
	n = &thrConn{
		Conn: c,
		r:    ratelimit.Reader(c, bk),
	}
	return
}

type quotaConn struct {
	net.Conn
	Quota uint64
	Cons  *uint64
}

func (c *quotaConn) Read(bs []byte) (n int, e error) {
	if c.Cons <= c.Quota {
		n, e = c.Read(bs)
	} else {
		e = DwnOverMsg(c.Quota)
	}
	if e == nil {
		rn := uint64(float32(n) * c.Cf)
		c.Cons = c.Cons + rn
	}
	return
}

type rspanConn struct {
	net.Conn
	cl clock.Clock
	sp *rs.RSpan
}

func (c *rspanConn) Read(bs []byte) (n int, e error) {
	nw := c.cl.Now()
	if c.sp.ContainsTime(nw) {
		n, e = c.Conn.Read(bs)
	} else {
		a, b := c.sp.CurrActIntv(nw)
		e = TimeOverMsg(a, b)
	}
	return
}

type Dialer interface {
	Dial(*net.TCPAddr, time.Duration, string) (net.Conn, error)
}

func interfaceConn(iface, addr string,
	timeout time.Duration, d Dialer) (c net.Conn, e error) {
	var ief *net.Interface
	ief, e = net.InterfaceByName(iface)
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var la *net.IPNet
	if e == nil {
		ok, i := false, 0
		for !ok && i != len(laddr) {
			la = laddr[i].(*net.IPNet)
			ok = la.IP.To4() != nil
			if !ok {
				i = i + 1
			}
		}
		if i == len(laddr) {
			e = fmt.Errorf("Not found IPv4 address")
		}
		// { found an IPv4 local address in laddr for dialing or error }
	}
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		c, e = d.Dial(tca, timeout, addr)
	}
	return
}

func proxyConn(p *gp.ProxyHttpServer,
	proxy, addr string) (n net.Conn, e error) {
	n, e = p.NewConnectDialToProxy(proxy)("tcp", addr)
	return
}

// DwnOverMsg quota over message
func DwnOverMsg(m uint64) (e error) {
	e = fmt.Errorf("Quota %d over", m)
	return
}

// TimeOverMsg time span over message
func TimeOverMsg(a, b time.Time) (e error) {
	e = fmt.Errorf("%s → %s", a.Format(time.RFC3339),
		b.Format(time.RFC3339))
	return
}

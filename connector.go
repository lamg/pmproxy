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
		e = InvCSpecErr(s)
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
			Cf:    s.Cf,
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
	rt *Rate
	net.Conn
	r io.Reader
}

func (c *thrConn) Read(bs []byte) (n int, e error) {
	n, e = c.r.Read(bs)
	return
}

func (c *thrConn) Close() (e error) {
	*c.rt.CurrConn = *c.rt.CurrConn - 1
	e = c.Conn.Close()
	return
}

func throttleConn(c net.Conn, r *Rate) (n net.Conn) {
	bk := ratelimit.NewBucket(r.TimeLapse, int64(r.Bytes))
	n = &thrConn{
		Conn: c,
		r:    ratelimit.Reader(c, bk),
		rt:   r,
	}
	return
}

type quotaConn struct {
	net.Conn
	Quota uint64
	Cons  *ConsAdd
	Cf    float32
}

func (c *quotaConn) Read(bs []byte) (n int, e error) {
	if c.Cons.CanGet(uint64(len(bs)), c.Quota, c.Cf) {
		n, e = c.Conn.Read(bs)
	} else {
		e = DwnOverMsg() // FIXME meaningless parameter
	}
	if e == nil {
		c.Cons.Add(uint64(n))
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
			e = NotIPv4Err()
		}
		// { found an IPv4 local address in laddr for dialing or error }
	}
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		c, e = d.Dial(tca, timeout, addr)
	}
	return
}

type IfaceProv interface {
	InterfaceByName(string) (*net.Interface., error)
}

type OSIfProv struct {
}

func (p *OSIfProv) InterfaceByName(name string) (n *net.Interface,
	e error) {
	n, e = net.InterfaceByName(name)
	return
}

type MIfaceProv struct {
	Mp map[string]*net.Interface
}

func (p *MIfaceProv) InterfaceByName(name string) (n *net.Interface,
e error){
	m, ok := p.Mp[name]
	if !ok {
		e = fmt.Errorf("Not found interface %s", name)// TODO make equal
		// to net.InterfaceByName error
	}
	return
}

func proxyConn(p *gp.ProxyHttpServer,
	proxy, addr string) (n net.Conn, e error) {
	n, e = p.NewConnectDialToProxy(proxy)("tcp", addr)
	return
}

// DwnOverMsg quota over message
func DwnOverMsg() (e error) {
	e = fmt.Errorf("Quota over")
	return
}

// TimeOverMsg time span over message
func TimeOverMsg(a, b time.Time) (e error) {
	e = fmt.Errorf("%s → %s", a.Format(time.RFC3339),
		b.Format(time.RFC3339))
	return
}

func InvCSpecErr(s *ConSpec) (e error) {
	e = fmt.Errorf("La conexión no puede completarse %v", s)
	return
}

func NotIPv4Err() (e error) {
	e = fmt.Errorf("Not found IPv4 address")
	return
}
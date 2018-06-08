package pmproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/juju/ratelimit"
	"github.com/lamg/clock"
	gp "github.com/lamg/proxy"
	rs "github.com/lamg/rtimespan"
)

// connect returns a connection according with the specifications
// in s
func connect(addr string, s *ConSpec, p *gp.Proxy,
	timeout time.Duration, cl clock.Clock, d Dialer,
	ifp IfaceProv) (c net.Conn, e error) {
	if !s.Valid() {
		e = InvCSpecErr(s)
	}
	if e == nil {
		if s.Proxy != "" {
			c, e = proxyConn(p, s.Proxy, addr)
		} else if s.Iface != "" {
			c, e = interfaceConn(s.Iface, addr, timeout, d, ifp)
		} else if s.Test {
			c = &bfConn{
				Buffer: bytes.NewBufferString(""),
				local: &net.TCPAddr{
					IP: []byte{10, 1, 1, 1},
				},
			}
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
		if s.Dm != nil {
			c = throttleConn(c, s.Dm)
		}
		if s.Cl != nil && s.Cl.AddConn(c.LocalAddr().String()) {
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

type bfConn struct {
	local  *net.TCPAddr
	remote *net.TCPAddr
	*bytes.Buffer
}

func (b *bfConn) Close() (e error) {
	return
}

func (b *bfConn) LocalAddr() (r net.Addr) {
	r = b.local
	return
}

func (b *bfConn) RemoteAddr() (r net.Addr) {
	r = b.remote
	return
}

func (b *bfConn) SetDeadline(t time.Time) (e error) {

	return
}

func (b *bfConn) SetReadDeadline(t time.Time) (e error) {
	return
}

func (b *bfConn) SetWriteDeadline(t time.Time) (e error) {
	return
}

type limitConn struct {
	net.Conn
	l *CLMng
}

func (c *limitConn) Close() (e error) {
	c.l.DecreaseAm(c.LocalAddr().String())
	e = c.Conn.Close()
	return
}

type thrConn struct {
	dm *DMng
	net.Conn
	r io.Reader
}

func (c *thrConn) Read(bs []byte) (n int, e error) {
	n, e = c.r.Read(bs)
	return
}

func (c *thrConn) Close() (e error) {
	c.dm.DecConn()
	e = c.Conn.Close()
	return
}

func throttleConn(c net.Conn, dm *DMng) (n net.Conn) {
	r := dm.IncConn()
	bk := ratelimit.NewBucket(r.TimeLapse, int64(r.Bytes))
	n = &thrConn{
		Conn: c,
		r:    ratelimit.Reader(c, bk),
		dm:   dm,
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
		e = DwnOverMsg()
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

func interfaceConn(iface, addr string, timeout time.Duration,
	d Dialer, ifp IfaceProv) (c net.Conn, e error) {
	var ief *net.Interface
	ief, e = ifp.InterfaceByName(iface)
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var la *net.IPNet
	if e == nil {
		if len(laddr) != 0 {
			la = laddr[0].(*net.IPNet)
		} else {
			e = NotIPErr()
		}
		// { found an IP local address in laddr for dialing or error }
	}
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		c, e = d.Dial(tca, timeout, addr)
	}
	return
}

type IfaceProv interface {
	InterfaceByName(string) (*net.Interface, error)
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
	e error) {
	var ok bool
	n, ok = p.Mp[name]
	if !ok {
		e = NotFoundIface(name)
	}
	return
}

func NotFoundIface(name string) (e error) {
	e = fmt.Errorf("Not found interface %s", name) // TODO make equal
	// to net.InterfaceByName error
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

func NotIPErr() (e error) {
	e = fmt.Errorf("Not found local IP address")
	return
}

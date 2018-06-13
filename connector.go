package pmproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	h "net/http"
	"net/url"
	"time"

	"github.com/juju/ratelimit"
	"github.com/lamg/clock"
	gp "github.com/lamg/proxy"
	rs "github.com/lamg/rtimespan"
)

// Connector provides DialContext for processing requests according
// rules defined, and using an *h.Transport
type Connector struct {
	Cl      clock.Clock
	Timeout time.Duration
	Ifp     IfaceProv
	Rd      []Det
}

// DialContext dials using as parameters fields in Connector,
// and *h.Request returned by ctx.Value(proxy.RequestKey)
func (n *Connector) DialContext(ctx context.Context, nt,
	addr string) (c net.Conn,
	e error) {
	r := ctx.Value(gp.ReqKey).(*h.Request)
	s := n.det(r)
	c, e = n.connect(r.Host, s)
	return
}

// Proxy returns the proxy URL for making a connection, according
// defined rules
func (n *Connector) Proxy(r *h.Request) (u *url.URL, e error) {
	s := n.det(r)
	if s.Proxy != "" {
		u, e = url.Parse(s.Proxy)
	}
	return
}

func (n *Connector) det(r *h.Request) (s *ConSpec) {
	s, nw := new(ConSpec), n.Cl.Now()
	for i := 0; i != len(n.Rd); i++ {
		n.Rd[i].Det(r, nw, s)
	}
	return
}

// connect returns a connection according with the specifications
// in s
func (n *Connector) connect(addr string, s *ConSpec) (c net.Conn,
	e error) {
	if !s.Valid() {
		e = InvCSpecErr(s)
	}
	if e == nil {
		if s.Iface != "" {
			c, e = n.interfaceConn(s.Iface, addr)
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
				cl:   n.Cl,
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

func (n *Connector) interfaceConn(iface, addr string) (c net.Conn,
	e error) {
	var ief *net.Interface
	ief, e = n.Ifp.InterfaceByName(iface)
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
		d := &net.Dialer{
			LocalAddr: tca,
		}
		c, e = d.Dial("tcp", addr)
	}
	return
}

// IfaceProv is made for easing testing while getting network
// interfaces by name
type IfaceProv interface {
	InterfaceByName(string) (*net.Interface, error)
}

// OSIfProv is the IfaceProv implementation using net.InterfaceByName
type OSIfProv struct {
}

// InterfaceByName returns the network interface associated with
// the supplied name
func (p *OSIfProv) InterfaceByName(name string) (n *net.Interface,
	e error) {
	n, e = net.InterfaceByName(name)
	return
}

// MIfaceProv is made for testing
type MIfaceProv struct {
	Mp map[string]*net.Interface
}

// InterfaceByName returns the network interface associated with
// the supplied name
func (p *MIfaceProv) InterfaceByName(name string) (n *net.Interface,
	e error) {
	var ok bool
	n, ok = p.Mp[name]
	if !ok {
		e = NotFoundIface(name)
	}
	return
}

// NotFoundIface error
func NotFoundIface(name string) (e error) {
	e = fmt.Errorf("Not found interface %s", name) // TODO make equal
	// to net.InterfaceByName error
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

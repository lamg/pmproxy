package pmproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
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
	Lg      *log.Logger
	Cl      clock.Clock
	Timeout time.Duration
	Tr      *h.Transport
	Dl      Dialer
	Rd      *SqDet
}

// DialContext dials using as parameters fields in Connector,
// and *h.Request returned by ctx.Value(proxy.ReqKey)
func (n *Connector) DialContext(ctx context.Context, nt,
	addr string) (c net.Conn,
	e error) {
	r := ctx.Value(gp.ReqKey).(*h.Request)
	s := n.det(r)
	c, e = n.connect(addr, s)
	if e == nil && n.Lg != nil {
		writeLog(n.Lg, r, nil, s.User, n.Cl.Now())
	}
	return
}

// RoundTrip logs a request and response processed returned
// by the underlying RoundTripper
func (n *Connector) RoundTrip(r *h.Request) (p *h.Response,
	e error) {
	p, e = n.Tr.RoundTrip(r)
	if e == nil {
		s := n.det(r)
		writeLog(n.Lg, r, p, s.User, n.Cl.Now())
		// log
	}
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
	n.Rd.Det(r, nw, s)
	return
}

// connect returns a connection according with the specifications
// in s
func (n *Connector) connect(addr string, s *ConSpec) (c net.Conn,
	e error) {
	if !s.Valid() {
		e = InvCSpec(s)
	}
	if e == nil {
		c, e = n.Dl.Dial(s.Iface, addr)
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

// Dialer is made for alternating between test dialer and os dialer
type Dialer interface {
	Dial(iface, addr string) (net.Conn, error)
}

// OSDialer is the Dialer implementation
type OSDialer struct {
	Timeout time.Duration
}

// Dial is the Dialer.Dial implementation
func (p *OSDialer) Dial(iface, addr string) (c net.Conn, e error) {
	var ief *net.Interface
	ief, e = net.InterfaceByName(iface)
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var la *net.IPNet
	if e == nil {
		if len(laddr) != 0 {
			la = laddr[0].(*net.IPNet)
		} else {
			e = NotLocalIP()
		}
		// { found an IP local address in laddr for dialing or error }
	}
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		d := &net.Dialer{
			LocalAddr: tca,
			Timeout:   p.Timeout,
		}
		c, e = d.Dial("tcp", addr)
	}
	return
}

// TestDialer is made for testing
type TestDialer struct {
	Mp map[string]map[string]string
}

// Dial is the Dialer.Dial implementation
func (p *TestDialer) Dial(iface, addr string) (c net.Conn, e error) {
	n, ok := p.Mp[iface]
	if !ok {
		e = NotFoundIface(iface)
	}
	var content string
	if e == nil {
		content, ok = n[addr]
		if !ok {
			e = NotFoundAddr(addr)
		}
	}
	if e == nil {
		c = &bfConn{
			Buffer: bytes.NewBufferString(content),
			// careful with nil pointers here
		}
	}
	return
}

// NotFoundAddr is the not found address error
func NotFoundAddr(addr string) (e error) {
	e = fmt.Errorf("Not found address %s", addr)
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

// InvCSpec is the invalid connection specification error
func InvCSpec(s *ConSpec) (e error) {
	e = fmt.Errorf("La conexión no puede completarse %v", s)
	return
}

// NotLocalIP is not found local IP address error
func NotLocalIP() (e error) {
	e = fmt.Errorf("Not found local IP address")
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

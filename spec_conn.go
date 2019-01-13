package pmproxy

import (
	"context"
	"fmt"
	"github.com/lamg/clock"
	"net"
	"net/http"
	"net/url"
	"time"
)

// In this file the package proxy refers to
//github.com/lamg/proxy package

// SpecCtx puts the correspondent *spec to each
// req in the context sent to DialContext
type SpecCtx struct {
	rs      *rspec
	clock   clock.Clock
	timeout func() time.Timeout
	lg      *logger
	crs     func(string) (*consR, bool)
}

type req *http.Request

type SpecKT string

var SpecK = SpecKT("spec")

type SpecV struct {
	s   *spec
	err error
}

func (p *SpecCtx) AddCtxValue(r req) (cr req) {
	tm := p.clock.Now()
	s, e := p.rs.spec(tm, r)
	if e == nil {
		e = p.lg.log(r)
	}
	ctx := r.Context()
	nctx := context.WithValue(ctx, SpecK,
		&SpecV{s: s, err: e})
	r.WithContext(nctx)
	return
}

// Proxy is made to be used by the *h.Transport used as
// h.RoundTripper by proxy.Proxy
func (p *SpecCtx) Proxy(r req) (u *url.URL,
	e error) {
	tm := p.clock.Now()
	var s *spec
	s, e = p.rs.Spec(tm, r)
	if e == nil && s.proxyURL != nil {
		u = s.proxyURL
	}
	return
}

// DialContext dials a connection according the *SpecV
// value
// passed in context by SpecCtx.AddCtxValue. For working
// according specification this function must be the
// DialContext of proxy.Proxy, and also the DialContext of
// the *h.Transport used as h.RoundTripper by proxy.Proxy
func (p *SpecCtx) DialContext(ctx context.Context,
	network, addr string) (c net.Conn, e error) {
	v := ctx.Value(SpecK)
	var s *spec
	if v != nil {
		sv, ok := v.(*SpecV)
		if ok {
			s, e = sv.s, sv.err
		} else {
			e = NoSpecValue()
		}
	} else {
		e = NoSpecKey(SpecK)
	}
	var n net.Conn
	if e == nil {
		n, e = dialIface(s.Iface, addr, p.timeout())
	}
	if e == nil {
		cr := make([]*consR, 0, len(s.Cr))
		inf := func(i int) {
			cs, ok := p.crs(s.Cr[i])
			if ok {
				cr = append(cr, cs)
			}
		}
		forall(inf, len(s.Cr))
		c, e = newRConn(cr, n)
	}
	return
}

func NoSpecKey(sk SpecKT) (e error) {
	e = fmt.Errorf("No spec key %s found", sk)
	return
}

func NoSpecValue() (e error) {
	e = fmt.Errorf("Value isn't of type *specV")
	return
}

func dialIface(iface, addr string,
	to time.Duration) (c net.Conn, e error) {
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
		// { found an IP local address in laddr for
		// dialing or error }
	}
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		d := &net.Dialer{
			LocalAddr: tca,
			Timeout:   to,
		}
		c, e = d.Dial("tcp", addr)
	}
	return
}

// NotLocalIP is the not found local IP address error
func NotLocalIP() (e error) {
	e = fmt.Errorf("Not found local IP address")
	return
}

// rConn is a restricted net connection by the consumption
// restrictors slice
type rConn struct {
	cr []*consR
	net.Conn
	raddr string
}

func newRConn(cr []*consR, c net.Conn) (r net.Conn,
	e error) {
	var raddr string
	raddr, _, e = net.SplitHostPort(c.RemoteAddr().String())
	if e == nil {
		ib := func(i int) (b bool) {
			b = !cr[i].open(raddr)
			return
		}
		b, _ := bLnSrch(ib, len(cr))
		if !b {
			// all cr[i].Open(raddr) return true
			r = &rConn{cr: cr, Conn: c, raddr: raddr}
		} else {
			c.Close()
			e = CannotOpen(raddr)
		}
	}

	return
}

func CannotOpen(raddr string) (e error) {
	e = fmt.Errorf("Cannot open connection from %s", raddr)
	return
}

func (r *rConn) Read(bs []byte) (n int, e error) {
	ib := func(i int) (b bool) {
		b = !r.cr[i].can(r.raddr, len(bs))
		return
	}
	b, _ := bLnSrch(ib, len(r.cr))
	n = 0
	if !b {
		// all r.cr[i].Can return true
		n, e = r.Conn.Read(bs)
	} else {
		e = CannotConsume(r.raddr)
	}
	if n != 0 {
		inf := func(i int) {
			r.cr[i].update(r.raddr, n)
		}
		forall(inf, len(r.cr))
	}
	return
}

func CannotConsume(raddr string) (e error) {
	e = fmt.Errorf("Cannot consume %s", raddr)
	return
}

func (r *rConn) Close() (e error) {
	inf := func(i int) {
		r.cr[i].Close(r.raddr)
	}
	forall(inf, len(r.cr))
	return
}

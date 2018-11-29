package pmproxy

import (
	"context"
	"fmt"
	"github.com/lamg/clock"
	"net"
	h "net/http"
	"net/url"
	"time"
)

// In this file the package proxy refers to github.com/lamg/proxy
// package

// SpecCtx puts the correspondent *Spec to each *h.Request in the
// context sent to DialContext
type SpecCtx struct {
	rs      RSpec
	clock   clock.Clock
	timeout time.Duration
	lg      *logger
}

type SpecKT string

var SpecK = SpecKT("spec")

type SpecV struct {
	s   *Spec
	err error
}

func (p *SpecCtx) AddCtxValue(r *h.Request) (cr *h.Request) {
	tm := p.clock.Now()
	s, e := p.rs.Spec(tm, r)
	if e == nil {
		e = p.lg.log(r)
	}
	ctx := r.Context()
	nctx := context.WithValue(ctx, SpecK, &SpecV{s: s, err: e})
	r.WithContext(nctx)
	return
}

// Proxy is made to be used by the *h.Transport used as
// h.RoundTripper by proxy.Proxy
func (p *SpecCtx) Proxy(r *h.Request) (u *url.URL, e error) {
	tm := p.clock.Now()
	var s *Spec
	s, e = p.rs.Spec(tm, r)
	if e == nil && s.ProxyURL != "" {
		u, e = url.Parse(s.ProxyURL)
	}
	return
}

// DialContext dials a connection according the *SpecV value
// passed in context by SpecCtx.AddCtxValue. For working according
// specification this function must be the DialContext of
// proxy.Proxy, and also the DialContext of the *h.Transport
// used as h.RoundTripper by proxy.Proxy
func (p *SpecCtx) DialContext(ctx context.Context, network,
	addr string) (c net.Conn, e error) {
	v := ctx.Value(SpecK)
	var s *Spec
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
		n, e = dialIface(s.Iface, addr, p.timeout)
	}
	if e == nil {
		c, e = newRConn(s.Cr, n)
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
		// { found an IP local address in laddr for dialing or error }
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
	cr []ConsR
	net.Conn
	raddr string
}

func newRConn(cr []ConsR, c net.Conn) (r net.Conn, e error) {
	var raddr string
	raddr, _, e = net.SplitHostPort(c.RemoteAddr().String())
	i, ok := 0, e == nil
	for ok && i != len(cr) {
		ok, i = cr[i].Open(raddr), i+1
	}
	if ok {
		r = &rConn{cr: cr, Conn: c, raddr: raddr}
	} else {
		c.Close()
		e = CannotOpen(raddr)
	}
	return
}

func CannotOpen(raddr string) (e error) {
	e = fmt.Errorf("Cannot open connection from %s", raddr)
	return
}

func (r *rConn) Read(bs []byte) (n int, e error) {
	i, ok := 0, true
	for ok && i != len(r.cr) {
		ok, i = r.cr[i].Can(r.raddr, len(bs)), i+1
	}
	n = 0
	if ok {
		n, e = r.Conn.Read(bs)
	} else {
		e = CannotConsume(r.raddr)
	}
	if n != 0 {
		for i := 0; i != len(r.cr); i++ {
			r.cr[i].UpdateCons(r.raddr, n)
		}
	}
	return
}

func CannotConsume(raddr string) (e error) {
	e = fmt.Errorf("Cannot consume %s", raddr)
	return
}

func (r *rConn) Close() (e error) {
	for i := 0; i != len(r.cr); i++ {
		r.cr[i].Close(r.raddr)
	}
	return
}

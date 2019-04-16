// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	"context"
	"fmt"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"net"
	"time"
)

// connMng has the values for controlling how
// the proxy (github.com/lamg/proxy) handles the connection
type connMng struct {
	maxIdle     int
	idleT       time.Duration
	tlsHT       time.Duration
	expCT       time.Duration
	dialTimeout time.Duration

	// these are initialized at conf.go
	log   func(string, string, string, string, time.Time) error
	match func(string, string, time.Time) *spec
	consR func(string) (*consR, bool)
	user  func(string) (string, bool)
}

func (p *connMng) set(ctx context.Context, meth, ürl,
	addr string, t time.Time) (nctx context.Context) {
	ip, _, e := net.SplitHostPort(addr)
	spec := p.match(ürl, ip, t)
	p.log(meth, ürl, spec.ip, spec.user, t)
	cp := &proxy.ConnParams{
		Iface:       spec.Iface,
		ParentProxy: spec.proxyURL,
		Modifiers:   spec.ConsRs,
		Error:       e,
	}
	if spec.Result.String != pred.TrueStr {
		cp.Error = fmt.Errorf("Match result '%s'",
			pred.String(spec.Result))
	}
	nctx = context.WithValue(ctx, specK, cp)
	return
}

func (p *connMng) params(ctx context.Context) (r *proxy.ConnParams) {
	v := ctx.Value(specK)
	if v != nil {
		r = v.(*proxy.ConnParams)
	}
	return
}

func (p *connMng) apply(n net.Conn, clientIP string,
	mods []string) (c net.Conn, e error) {
	cr := make([]*consR, 0, len(mods))
	inf := func(i int) {
		cs, ok := p.consR(mods[i])
		if ok {
			cr = append(cr, cs)
		}
	}
	forall(inf, len(mods))
	u, _ := p.user(clientIP)
	c, e = newRConn(cr, clientIP, u, n)
	return
}

func (p *connMng) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		nameK:    proxyTr,
		timeoutK: p.dialTimeout.String(),
		maxIdleK: p.maxIdle,
		idleTK:   p.idleT,
		tlsHTK:   p.tlsHT,
		expCTK:   p.expCT,
	}
	return
}

func (p *connMng) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			maxIdleK,
			func(i interface{}) {
				p.maxIdle = intE(i, fe)
			},
		},
		{
			idleTK,
			func(i interface{}) {
				p.idleT = durationE(i, fe)
			},
		},
		{
			tlsHTK,
			func(i interface{}) {
				p.tlsHT = durationE(i, fe)
			},
		},
		{
			expCTK,
			func(i interface{}) {
				p.expCT = durationE(i, fe)
			},
		},
		{
			timeoutK,
			func(i interface{}) {
				p.dialTimeout = durationE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

// rConn is a restricted net connection by the consumption
// restrictors slice
type rConn struct {
	cr []*consR
	net.Conn
	raddr string
	user  string
}

func newRConn(cr []*consR, ip, user string,
	c net.Conn) (r net.Conn, e error) {
	if e == nil {
		ib := func(i int) (b bool) {
			b = !cr[i].open(ip, user)
			return
		}
		b, _ := bLnSrch(ib, len(cr))
		if !b {
			// all cr[i].Open(raddr) return true
			r = &rConn{cr: cr, Conn: c, raddr: ip, user: user}
		} else {
			c.Close()
			e = cannotOpen(ip)
		}
	}
	return
}

func (r *rConn) Read(bs []byte) (n int, e error) {
	ib := func(i int) (b bool) {
		b = !r.cr[i].can(r.raddr, r.user, len(bs))
		return
	}
	b, _ := bLnSrch(ib, len(r.cr))
	n = 0
	if !b {
		// all r.cr[i].Can return true
		n, e = r.Conn.Read(bs)
	} else {
		e = cannotConsume(r.raddr)
	}
	if n != 0 {
		inf := func(i int) {
			r.cr[i].update(r.raddr, r.user, n)
		}
		forall(inf, len(r.cr))
	}
	return
}

func (r *rConn) Close() (e error) {
	inf := func(i int) {
		r.cr[i].close(r.raddr, r.user)
	}
	forall(inf, len(r.cr))
	return
}

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
	"net"
	"time"
)

type dialer struct {
	timeout time.Duration
	consRF  func(string) (*consR, bool)
}

func (d *dialer) managerKF(c *cmd) (kf []kFunc) {
	// TODO
	return
}

func (d *dialer) dialContext(ctx context.Context,
	network, addr string) (c net.Conn, e error) {
	v := ctx.Value(specK)
	s, ok := v.(*spec)
	if !ok {
		e = noKey(string(specK))
	}
	if e == nil {
		if (s.Iface == "") == (s.proxyURL == nil) ||
			len(s.ConsRs) == 0 {
			e = invalidSpec(s)
		}
	}
	var n net.Conn
	if e == nil {
		n, e = dialIface(s.Iface, addr, d.timeout)
	}
	if e == nil {
		cr := make([]*consR, 0, len(s.ConsRs))
		inf := func(i int) {
			cs, ok := d.consRF(s.ConsRs[i])
			if ok {
				cr = append(cr, cs)
			}
		}
		forall(inf, len(s.ConsRs))
		c, e = newRConn(cr, s.ip, s.user, n)
	}
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
			e = noLocalIP()
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

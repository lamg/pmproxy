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
	"github.com/lamg/viper"
	"net"
	"time"
)

type dialer struct {
	timeout time.Duration
	lg      *logger
	consRF  func(string) (*consR, bool)
}

const (
	timeoutK   = "timeout"
	dialerName = "dialer"
)

func newDialer(consRF func(string) (*consR, bool),
	lg *logger) (d *dialer) {
	d = &dialer{
		timeout: viper.GetDuration(timeoutK),
		lg:      lg,
		consRF:  consRF,
	}
	return
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
			len(s.ConsR) == 0 {
			e = invalidSpec(s)
		}
	}
	var n net.Conn
	if e == nil {
		n, e = dialIface(s.Iface, addr, d.timeout)
	}
	if e == nil {
		cr := make([]*consR, 0, len(s.ConsR))
		inf := func(i int) {
			cs, ok := d.consRF(s.ConsR[i])
			if ok {
				cr = append(cr, cs)
			}
		}
		forall(inf, len(s.ConsR))
		c, e = newRConn(cr, n)
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
			e = cannotOpen(raddr)
		}
	}

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
		e = cannotConsume(r.raddr)
	}
	if n != 0 {
		inf := func(i int) {
			r.cr[i].update(r.raddr, n)
		}
		forall(inf, len(r.cr))
	}
	return
}

func (r *rConn) Close() (e error) {
	inf := func(i int) {
		r.cr[i].close(r.raddr)
	}
	forall(inf, len(r.cr))
	return
}

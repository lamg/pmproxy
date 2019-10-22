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

package managers

import (
	"context"
	"github.com/lamg/proxy"
	gp "golang.org/x/net/proxy"
	"net"
	"time"
)

type Dialer struct {
	cf      *conf
	cmdf    CmdF
	Timeout time.Duration
	Dialer  func(string, time.Duration) gp.Dialer
}

func (d *Dialer) DialContext(ctx context.Context, network,
	addr string) (c net.Conn, e error) {
	rqp := ctx.Value(proxy.ReqParamsK).(*proxy.ReqParams)
	m := &Cmd{
		Manager: connectionsMng,
		Cmd:     Open,
		IP:      rqp.IP,
		rqp:     rqp,
	}
	d.cmdf(m)
	e = m.Err
	if e == nil {
		dlr := d.Dialer(m.iface, d.Timeout)
		if m.parentProxy != nil {
			c, e = proxy.DialProxy(network, addr, m.parentProxy, dlr)
		} else {
			c, e = dlr.Dial(network, addr)
		}
	}
	if e == nil {
		c = &ctlConn{cmdf: d.cmdf, Conn: c, rqp: rqp}
	}
	return
}

type ctlConn struct {
	cmdf CmdF
	rqp  *proxy.ReqParams
	net.Conn
}

func (c *ctlConn) Read(p []byte) (n int, e error) {
	e = c.operation(readRequest, len(p))
	if e == nil {
		n, e = c.Conn.Read(p)
	}
	if n != 0 {
		e = c.operation(readReport, n)
	}
	return
}

func (c *ctlConn) Close() (e error) {
	e = c.Conn.Close()
	return
}

func (c *ctlConn) operation(op string, amount int) (e error) {
	m := &Cmd{
		Cmd:     op,
		Manager: connectionsMng,
		IP:      c.rqp.IP,
		Uint64:  uint64(amount),
		rqp:     c.rqp,
	}
	c.cmdf(m)
	e = m.Err
	return
}

func NetDialerF(iface string, timeout time.Duration) (d gp.Dialer) {
	d = &proxy.IfaceDialer{
		Timeout:   timeout,
		Interface: iface,
	}
	return
}

func MockDialerF(iface string,
	timeout time.Duration) (d gp.Dialer) {
	d = new(mockDialer)
	return
}

type mockDialer struct {
}

func (d *mockDialer) Dial(network, addr string) (c net.Conn,
	e error) {
	c = new(mockConn)
	return
}

type mockConn struct{}

func (c *mockConn) Read(p []byte) (int, error) {
	return len(p), nil
}
func (c *mockConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *mockConn) Close() error                      { return nil }
func (c *mockConn) LocalAddr() net.Addr               { return nil }
func (c *mockConn) RemoteAddr() net.Addr              { return nil }
func (c *mockConn) SetDeadline(t time.Time) error     { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error { return nil }

func (c *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

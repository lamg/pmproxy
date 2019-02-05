package pmproxy

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
	lg *logger) (d proxy.DialContext,
	a *adminName,
	fs func() interface{},
	e error) {
	dl := &dialer{
		timeout: viper.GetDuration(timeoutK),
		lg:      lg,
		consRF:  consRF,
	}
	a = &adminName{
		name: dialerName,
		admin: []kRes{
			{
				get,
				func() (bs []byte, e error) {
					bs = []byte(dl.timeout.String())
					return
				},
			},
		},
	}
	d = dl.dialContext
	return
}

func (d *dialer) dialContext(ctx context.Context,
	network, addr string) (c net.Conn, e error) {
	v := ctx.Value(specK)
	var s *spec
	if v != nil {
		sv, ok := v.(*specV)
		if ok {
			s, e = sv.s, sv.err
		} else {
			e = noSpecValue()
		}
	} else {
		e = noSpecKey(specK)
	}
	var n net.Conn
	if e == nil {
		n, e = dialIface(s.Iface, addr, p.timeout)
	}
	if e == nil {
		cr := make([]*consR, 0, len(s.ConsR))
		inf := func(i int) {
			cs, ok := p.consRF(s.consR[i])
			if ok {
				cr = append(cr, cs)
			}
		}
		forall(inf, len(s.consR))
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

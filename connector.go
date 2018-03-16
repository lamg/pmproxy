package pmproxy

import (
	"fmt"
	"net"
	"time"

	"github.com/lamg/clock"
	"golang.org/x/tools/godoc/util"
)

type rConn struct {
	cl clock.Clock
	net.Conn
	qt uint64
	cs *uint64
	lm *util.Throttle
}

func newRConn(cl clock.Clock, s *ConSpec, addr string) (r *rConn,
	e error) {
	var ief *net.Interface
	ief, e = net.InterfaceByName(qc.Qt.Iface)
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var la *net.IPNet
	if e == nil {
		ok, i := false, 0
		for !ok && i != len(laddr) {
			la = laddr[i].(*net.IPNet)
			ok = la.IP.To4() != nil
			if !ok {
				i = i + 1
			}
		}
		if i == len(addr) {
			e = fmt.Errorf("Not found IPv4 address")
		}
	}
	var cn net.Conn
	if e == nil {
		// TODO reemplazar el dialer por uno
		// que sirva para hacer pruebas
		tca := &net.TCPAddr{IP: la.IP}
		d := &net.Dialer{
			LocalAddr: tca,
			Timeout:   10 * time.Second,
		}
		cn, e = d.Dial("tcp", addr)
	}
	// { set connection interface }
	if e == nil {
		r = &rConn{Conn: cn, qc: qc,
			lm: util.NewThrottle(qc.Qt.Thr, time.Millisecond),
		}
	}
	return
}

func (r *rConn) Read(p []byte) (n int, e error) {
	r.lm.Throttle()
	nw := r.cl.Now()
	if r.qc.Cs.Dwn == r.qc.Qt.Dwn {
		e = DwnOverMsg(r.qc.Qt.Dwn)
	}
	if e == nil && !r.qc.Qt.Span.ContainsTime(nw) {
		a, b := r.qc.Qt.Span.CurrActIntv(nw)
		e = TimeOverMsg(a, b)
	}
	if e == nil {
		n, e = r.Conn.Read(p)
	}
	if e == nil {
		r.qc.Cs.Dwn += uint64(n)
	}
	return
}

func (r *rConn) Close() (e error) {
	if r.qc.Cs.Cns != 0 {
		r.qc.Cs.Cns = r.qc.Cs.Cns - 1
	}
	e = r.Conn.Close()
	return
}

// DwnOverMsg quota over message
func DwnOverMsg(m uint64) (e error) {
	e = fmt.Errorf("Quota %d over", m)
	return
}

// TimeOverMsg time span over message
func TimeOverMsg(a, b time.Time) (e error) {
	e = fmt.Errorf("%s → %s", a.Format(time.RFC3339),
		b.Format(time.RFC3339))
	return
}

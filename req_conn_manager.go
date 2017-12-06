package pmproxy

import (
	"fmt"
	"net"
	h "net/http"
	"strings"
	"time"

	"github.com/lamg/errors"
	"github.com/lamg/pmproxy/util"
)

// RRConnMng manages requests, responses and connections
// made to the proxy server, according the program
// configuration
type RRConnMng struct {
	qa *QAdm
	rl *RLog
	uf map[string]string
	ts map[string]float64
}

// NewRRConnMng creates a new RRConnMng
func NewRRConnMng(q *QAdm, l *RLog,
	u map[string]string,
	t map[string]float64) (r *RRConnMng) {
	r = &RRConnMng{q, l, u, t}
	return
}

// GetConn returns a new connection processed
// according configured requirements
func (m *RRConnMng) GetConn(nt, ad string,
	r *h.Request) (c net.Conn, e error) {
	return
}

// CauseCD represents the cause a request cannot
// be processed
type CauseCD struct {
	Type string
	Data string
}

// CanDo says wether the request can be
// processed at the supplied time
// TODO return the cause when !y
func (m *RRConnMng) CanDo(r *h.Request) (d *CauseCD) {
	hs, pr, _ := net.SplitHostPort(r.Host)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	_, d = m.qa.canReq(ip, hs, pr)
	return
}

// ProcResponse process responses according configuration
func (m *RRConnMng) ProcResponse(p *h.Response) (r *h.Response) {
	var log *Log
	if r != nil {
		tm := time.Now()
		log = &Log{
			// User is set by p.rl.Log
			Addr:      r.Request.RemoteAddr,
			Meth:      r.Request.Method,
			URI:       r.Request.URL.String(),
			Proto:     r.Request.Proto,
			Time:      tm,
			Elapsed:   5 * time.Millisecond, //FIXME not the meaning of E.
			From:      "-",
			Action:    "TCP_MISS",
			Hierarchy: "DIRECT",
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "-"
		} else {
			ct = strings.Split(ct, ";")[0]
			// MIME type parameters droped
		}
		log.ContentType = ct
		m.rl.record(log)
	}
	r = p
	return
}

func (m *RRConnMng) newConn(ntw, addr string,
	r *h.Request, t time.Time) (c net.Conn, e error) {
	n, er := m.getUsrNtIf(r.RemoteAddr)
	e = errors.UnwrapErr(er)
	var ief *net.Interface
	if e == nil {
		ief, e = net.InterfaceByName(n)
	}
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
		tca := &net.TCPAddr{IP: la.IP}
		d := &net.Dialer{
			LocalAddr: tca,
			Timeout:   10 * time.Second,
		}
		cn, e = d.Dial(ntw, addr)
	}
	var ts float64
	if e == nil {
		ts, e = m.getThrottle(r.RemoteAddr)
	}
	var thr *util.Throttle
	if e == nil {
		thr = util.NewThrottle(ts, time.Millisecond)
	}
	if e == nil {
		r := &conCount{cn, m.qa, addr, r.RemoteAddr}
		c = newThConn(r, thr)
	}
	return
}

type thConn struct {
	net.Conn
	thr *util.Throttle
}

func newThConn(c net.Conn, thr *util.Throttle) (b *thConn) {
	b = &thConn{c, thr}
	return
}

func (b *thConn) Read(p []byte) (n int, e error) {
	b.thr.Throttle()
	n, e = b.Conn.Read(p)
	return
}

func (b *thConn) Write(p []byte) (n int, e error) {
	n, e = b.Conn.Write(p)
	return
}

func (m *RRConnMng) getUsrNtIf(r string) (n string,
	e *errors.Error) {
	ip, _, ec := net.SplitHostPort(r)
	e = errors.NewForwardErr(ec)
	var u *User
	if e == nil {
		u, ec = m.qa.sm.User(ip)
		e = errors.NewForwardErr(ec)
	}
	if e == nil {
		var ok bool
		n, ok = m.uf[u.QuotaGroup]
		if !ok {
			e = errors.NewForwardErr(
				fmt.Errorf("Not found interface for %s", u.QuotaGroup))
		}
	}
	return
}

// getThrottle returns the duration and capacity for
// using it rl.NewBucket
func (m *RRConnMng) getThrottle(r string) (t float64,
	e error) {
	var ip string
	ip, _, e = net.SplitHostPort(r)
	var u *User
	if e == nil {
		u, e = m.qa.sm.User(ip)
	}
	if e == nil {
		var ok bool
		t, ok = m.ts[u.QuotaGroup]
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorKey,
				Err:  fmt.Errorf("Not found key %s", u.QuotaGroup),
			}
		}
	}
	return
}

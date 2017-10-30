package pmproxy

import (
	"fmt"
	"net"
	h "net/http"
	"strings"
	"time"

	dl "github.com/lamg/dialer"
	"github.com/lamg/errors"
)

// RRConnMng manages requests, responses and connections
// made to the proxy server, according the program
// configuration
type RRConnMng struct {
	dlr dl.Dialer
	qa  *QAdm
	rl  *RLog
	uf  map[string]string
}

// NewRRConnMng creates a new RRConnMng
func NewRRConnMng(d dl.Dialer, q *QAdm,
	l *RLog, u map[string]string) (r *RRConnMng) {
	r = &RRConnMng{d, q, l, u}
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
func (m *RRConnMng) CanDo(r *h.Request, t time.Time) (d *CauseCD) {
	hs, pr, _ := net.SplitHostPort(r.Host)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	_, d = m.qa.canReq(ip, hs, pr, t)
	return
}

// TODO candidate for QAdm method
func getK(qa *QAdm, host, raddr string) (k float32, ip string) {
	hs, pr, _ := net.SplitHostPort(host)
	ip, _, _ = net.SplitHostPort(raddr)
	k, _ = qa.canReq(ip, hs, pr, time.Now())
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
		k, ip := getK(m.qa, r.Request.Host, r.Request.RemoteAddr)
		if k > 0 {
			cs := float32(r.Request.ContentLength) * k
			m.qa.addCons(ip, uint64(cs))
		}
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
		d := &net.Dialer{LocalAddr: tca}
		cn, e = d.Dial(ntw, addr)
	}
	if e == nil {
		c = &conCount{cn, m.qa, addr, r.RemoteAddr}
	}
	return
}

func (m *RRConnMng) getUsrNtIf(r string) (n string,
	e *errors.Error) {
	h, _, ec := net.SplitHostPort(r)
	e = errors.NewForwardErr(ec)
	var v interface{}
	if e == nil {
		var ok bool
		v, ok = m.qa.sm.sessions.Load(h)
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorKey,
				Err: fmt.Errorf("Not found key %s in p.qa.sm.sessions",
					h),
			}
		}
	}
	var u *User
	if e == nil {
		var ok bool
		u, ok = v.(*User)
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorTypeAssertion,
				Err:  fmt.Errorf("v is not an *User"),
			}
		}
	}
	if e == nil {
		var ok bool
		n, ok = m.uf[u.QuotaGroup]
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorKey,
				Err:  fmt.Errorf("Not found key %s", u.QuotaGroup),
			}
		}
	}
	return
}

type conCount struct {
	net.Conn
	qa    *QAdm
	addr  string
	rAddr string
}

func (c *conCount) Read(p []byte) (n int, e error) {
	k, ip := getK(c.qa, c.addr, c.rAddr)
	if k >= 0 {
		n, e = c.Conn.Read(p)
		// { n ≥ 0 }
		cs := k * float32(n)
		c.qa.addCons(ip, uint64(cs))
	} else {
		e = fmt.Errorf("No tiene acceso")
	}
	return
}

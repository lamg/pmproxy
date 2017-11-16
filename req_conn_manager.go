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
		println(e == nil)
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

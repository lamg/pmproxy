package pmproxy

import (
	"fmt"
	g "github.com/lamg/goproxy"
	"net"
	h "net/http"
	"strings"
	"time"
)

// PMProxy is the proxy server
type PMProxy struct {
	qa *QAdm
	px *g.ProxyHttpServer
	rl *RLog
	uf map[string]string
}

// NewPMProxy creates a new PMProxy
func NewPMProxy(qa *QAdm, rl *RLog,
	uf map[string]string) (p *PMProxy) {
	p = &PMProxy{qa, g.NewProxyHttpServer(), rl, uf}
	p.px.OnRequest(g.ReqConditionFunc(p.cannotRequest)).
		DoFunc(forbiddenAcc)
	p.px.OnResponse().DoFunc(p.logResp)
	p.px.ConnectDial = p.newConCount
	p.px.NonproxyHandler = h.HandlerFunc(localHandler)
	return
}

func localHandler(w h.ResponseWriter, r *h.Request) {
	w.WriteHeader(h.StatusNotFound)
}

func forbiddenAcc(r *h.Request,
	c *g.ProxyCtx) (q *h.Request, p *h.Response) {
	q, p = r, g.NewResponse(r, "text/plain",
		h.StatusForbidden, "No tiene acceso")
	return
}

func (p *PMProxy) newConCount(ntw, addr string,
	c *g.ProxyCtx) (r net.Conn, e error) {
	// TODO
	// if address is a host name then it can be stored
	// in new cn to used by canReq
	var n string
	n, e = p.getUsrNtIf(c.Req)
	var ief *net.Interface
	if e == nil {
		ief, e = net.InterfaceByName(n)
	}
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var d *net.Dialer
	if e == nil {
		// DOUBT 0 seems to be the IPv4 address and
		// 1 the IPv6 address
		println(len(laddr))
		println(laddr[0].String())
		d = &net.Dialer{LocalAddr: laddr[0]}
	}
	var cn net.Conn
	if e == nil {
		cn, e = d.Dial(ntw, addr)
	}
	if e == nil {
		r = &conCount{cn, p.qa, addr, c}
	}
	return
}

func (p *PMProxy) getUsrNtIf(r *h.Request) (n string, e error) {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		v, ok := p.qa.sm.sessions.Load(h)
		var u *User
		if ok {
			u = v.(*User)
			n = p.uf[u.QuotaGroup]
		}
	}
	return
}

type conCount struct {
	net.Conn
	qa   *QAdm
	addr string
	ctx  *g.ProxyCtx
}

func (c *conCount) Read(p []byte) (n int, e error) {
	ip, _, _ := net.SplitHostPort(c.ctx.Req.RemoteAddr)
	hs, pr, _ := net.SplitHostPort(c.ctx.Req.Host)
	k := c.qa.canReq(ip, hs, pr, time.Now())
	if k >= 0 {
		n, e = c.Conn.Read(p)
		// { n ≥ 0 }
		cs := k * float32(n)
		c.qa.addCons(ip, uint64(cs))
	} else {
		p = []byte(fmt.Sprintf("Cannot request %s:%s from %s at this time", hs, pr, ip))
		n = len(p)
	}
	return
}

type usrDt struct {
	cf   float32
	req  *h.Request
	time time.Time
}

func (p *PMProxy) logResp(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
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
		p.rl.record(log)
	}
	x = r
	return
}

func (p *PMProxy) cannotRequest(q *h.Request,
	c *g.ProxyCtx) (r bool) {
	hs, pr, _ := net.SplitHostPort(q.Host)
	ra, _, _ := net.SplitHostPort(q.RemoteAddr)
	k := p.qa.canReq(ra, hs, pr, time.Now())
	c.UserData = &usrDt{
		cf:  k,
		req: q,
	}
	r = k < 0
	return
}

func (p *PMProxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.px.ServeHTTP(w, r)
}

// Dialer is an interface to custom dialers that
// can be used in place of net.Dial
type Dialer interface {
	Dial(string, string) (net.Conn, error)
}

// NetDialer is a Dialer that uses net.Dial
type NetDialer struct {
}

// Dial dials using net.Dial
func (n *NetDialer) Dial(ntw,
	addr string) (c net.Conn, e error) {
	c, e = net.Dial(ntw, addr)
	return
}

package pmproxy

import (
	"github.com/elazarl/goproxy"
	g "github.com/elazarl/goproxy"
	"net"
	h "net/http"
	"strings"
	"time"
)

type proxy struct {
	qa *QAdm
	px *g.ProxyHttpServer
	rl *RLog
}

func newProxy(qa *QAdm, rl *RLog) (p *proxy) {
	p = new(proxy)
	p.px, p.qa, p.rl = g.NewProxyHttpServer(), qa, rl
	// TODO instead of handling with goproxy.AlwaysReject
	// use a handler that returns an html page with useful
	// information for the user
	p.px.OnRequest(goproxy.ReqConditionFunc(p.cannotRequest)).
		HandleConnect(goproxy.AlwaysReject)
	p.px.OnResponse().DoFunc(p.logResp)
	p.px.ConnectDial = p.newConCount
	// TODO p.px.NonproxyHandler = hl
	// Reject all connections not made throug port 443 or 80
	return
}

func (p *proxy) newConCount(ntw, addr string, c *g.ProxyCtx) (r net.Conn,
	e error) {
	// TODO
	// if address is a host name then it can be stored
	// in new cn to used by canReq
	var cn net.Conn
	cn, e = net.Dial(ntw, addr)
	if e == nil {
		r = &conCount{cn, p.qa, addr, c.Req}
	}
	return
}

type conCount struct {
	net.Conn
	qa   *QAdm
	addr string
	req  *h.Request
}

func (c *conCount) Read(p []byte) (n int, e error) {
	// TODO test
	ip, addr := trimPort(c.req.RemoteAddr),
		c.req.URL.Host
	k := c.qa.canReq(ip, addr, time.Now())
	if k >= 0 {
		n, e = c.Conn.Read(p)
		// { n ≥ 0 }
		cs := k * float32(n)
		c.qa.addCons(ip, uint64(cs))
	}
	return
}

type usrDt struct {
	cf   float32
	req  *h.Request
	time time.Time
}

func (p *proxy) logResp(r *h.Response,
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

func (p *proxy) cannotRequest(q *h.Request,
	c *goproxy.ProxyCtx) (r bool) {
	k := p.qa.canReq(trimPort(q.RemoteAddr), q.URL.Host, time.Now())
	c.UserData = &usrDt{
		cf:  k,
		req: q,
	}
	r = k < 0
	return
}

func (p *proxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.px.ServeHTTP(w, r)
}

package pmproxy

import (
	"github.com/elazarl/goproxy"
	g "github.com/elazarl/goproxy"
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
	nd Dialer
}

// NewPMProxy creates a new PMProxy
func NewPMProxy(qa *QAdm, rl *RLog, nd Dialer) (p *PMProxy) {
	p = &PMProxy{qa, g.NewProxyHttpServer(), rl, nd}
	// TODO instead of handling with goproxy.AlwaysReject
	// use a handler that returns an html page with useful
	// information for the user
	p.px.OnRequest(goproxy.ReqConditionFunc(p.cannotRequest)).
		HandleConnect(goproxy.AlwaysReject)
	p.px.OnResponse().DoFunc(p.logResp)
	p.px.ConnectDial = p.newConCount
	p.px.NonproxyHandler = newLocalHn(qa)
	// Reject all connections not made throug port 443 or 80
	return
}

func (p *PMProxy) newConCount(ntw, addr string,
	c *g.ProxyCtx) (r net.Conn, e error) {
	// TODO
	// if address is a host name then it can be stored
	// in new cn to used by canReq
	var cn net.Conn
	cn, e = p.nd.Dial(ntw, addr)
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
	ip := trimPort(c.req.RemoteAddr)
	k := c.qa.canReq(ip, c.req.URL.Hostname(),
		c.req.URL.Port(), time.Now())
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
	c *goproxy.ProxyCtx) (r bool) {
	k := p.qa.canReq(trimPort(q.RemoteAddr), q.URL.Hostname(), q.URL.Port(), time.Now())
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

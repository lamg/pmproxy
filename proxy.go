package pmproxy

import (
	"github.com/elazarl/goproxy"
	g "github.com/elazarl/goproxy"
	_ "net"
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
	// p.px.ConnectDial = newConCount
	p.px.OnRequest(
		goproxy.ReqConditionFunc(
			p.cannotRequest)).HandleConnect(goproxy.AlwaysReject)
	p.px.OnResponse().DoFunc(p.updateConsumption)
	// Reject all connections not made throug port 443 or 80
	return
}

// func newConCount(ntw, addr string) (r net.Conn, e error) {

// 	return
// }

type conCount struct {
}

type usrDt struct {
	cf   float32
	req  *h.Request
	time time.Time
}

func (p *proxy) updateConsumption(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
	var k float32
	var log *Log
	if r != nil {
		tm := time.Now()
		k = p.qa.canReq(trimPort(r.Request.RemoteAddr),
			r.Request.URL, tm)
		log = &Log{
			// User is set by p.rl.Log
			Addr:    r.Request.RemoteAddr,
			Meth:    r.Request.Method,
			URI:     r.Request.URL.String(),
			Proto:   r.Request.Proto,
			Time:    tm,
			Elapsed: 5 * time.Millisecond, //FIXME not the meaning of E.
			From:    "-",
		}
	} else {
		k = -1
	}
	// { (r ≠ nil ≡ log ≠ nil) ∧ (r = nil ≡ log = nil ∧ k = -1) }
	if k >= 0 {
		cl := float32(r.ContentLength)
		p.qa.addCons(trimPort(r.Request.RemoteAddr), uint64(k*cl))
		log.RespSize = uint64(r.ContentLength)
		log.Action = "TCP_MISS"
		log.Hierarchy = "DIRECT"
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "-"
		} else {
			ct = strings.Split(ct, ";")[0]
			// MIME type parameters droped
		}
		log.ContentType = ct
		x = r
	} else if log != nil {
		log.Action = "TCP_DENIED"
		log.Hierarchy = "NONE"
		log.ContentType = "text/plain"
		x = g.NewResponse(r.Request, "text/plain", h.StatusForbidden,
			"No hay acceso a Internet")
		p.rl.record(log)
	}

	return
}

func (p *proxy) cannotRequest(q *h.Request,
	c *goproxy.ProxyCtx) (r bool) {
	k := p.qa.canReq(trimPort(q.RemoteAddr), q.URL, time.Now())
	c.UserData = &usrDt{
		cf:  k,
		req: q,
	}
	r = k < 0
	return
}

func (p *proxy) canResponse(r *h.Response,
	c *goproxy.ProxyCtx) (x bool) {
	k := p.qa.canReq(trimPort(r.Request.RemoteAddr), r.Request.URL, time.Now())
	x = k >= 0
	return
}

func (p *proxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.px.ServeHTTP(w, r)
}

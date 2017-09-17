package pmproxy

import (
	g "github.com/elazarl/goproxy"
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
	p.px.OnRequest().DoFunc(p.restrictAccess)
	p.px.OnResponse().DoFunc(p.updateConsumption)
	return
}

func (p *proxy) restrictAccess(r *h.Request,
	c *g.ProxyCtx) (x *h.Request, y *h.Response) {
	ud := &usrDt{
		cf:  p.qa.canReq(r.RemoteAddr, r.URL, time.Now()),
		req: r,
	}
	x = r
	if ud.cf < 0 {
		y = g.NewResponse(r, g.ContentTypeText, h.StatusForbidden,
			"No puede acceder al recurso")
		// { c.UserData = nil }
	} else {
		y, ud.time = nil, time.Now()
		c.UserData = ud
	}
	return
}

type usrDt struct {
	cf   float32
	req  *h.Request
	time time.Time
}

func (p *proxy) updateConsumption(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
	var ud *usrDt
	var log *Log
	if c.UserData != nil {
		ud = c.UserData.(*usrDt)
		log = &Log{
			// User is set by p.rl.Log
			Addr:    ud.req.RemoteAddr,
			Meth:    ud.req.Method,
			URI:     ud.req.URL.String(),
			Proto:   ud.req.Proto,
			Time:    time.Now(),
			Elapsed: ud.time.Sub(time.Now()),
			From:    "-",
		}
	}
	if ud != nil && r != nil {
		cl := float32(r.ContentLength)
		p.qa.addCons(ud.req.RemoteAddr, uint64(ud.cf*cl))
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
	} else if ud != nil && r == nil {
		log.Action = "TCP_DENIED"
		log.Hierarchy = "NONE"
		log.ContentType = "text/plain"
		r = g.NewResponse(ud.req, "text/plain", h.StatusNotFound,
			"No hay acceso a Internet")
	}
	if ud != nil {
		p.rl.record(log)
	}
	x = r
	return
}

func (p *proxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.px.ServeHTTP(w, r)
}

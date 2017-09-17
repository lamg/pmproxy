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

func (p *proxy) Init(qa *QAdm, rl *RLog) {
	p.px, p.qa, p.rl = g.NewProxyHttpServer(), qa, rl
	p.px.OnRequest().DoFunc(p.restrictAccess)
	p.px.OnResponse().DoFunc(p.updateConsumption)
}

func (p *proxy) restrictAccess(r *h.Request,
	c *g.ProxyCtx) (x *h.Request, y *h.Response) {
	ud := new(usrDt)
	ud.cf, x = p.qa.canReq(r.RemoteAddr, r.URL, time.Now()), r
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
	time time.Time
}

func (p *proxy) updateConsumption(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
	// { c.UserData ≠ nil ∧ c.UserData has type *usrDt }
	var ud *usrDt
	var cl float32
	x, ud, cl = r, c.UserData.(*usrDt), float32(r.ContentLength)
	p.qa.addCons(r.Request.RemoteAddr, uint64(ud.cf*cl))
	// RLog
	var log *Log
	log = &Log{
		Addr:       r.Request.RemoteAddr,
		Meth:       r.Request.Method,
		URI:        r.Request.URL.String(),
		Proto:      r.Request.Proto,
		StatusCode: r.StatusCode,
		RespSize:   uint64(r.ContentLength),
		Time:       time.Now(),
		Elapsed:    ud.time.Sub(time.Now()),
		Action:     "TCP_MISS",
		Hierarchy:  "DIRECT",
		From:       "-",
	}
	var ct string //content type
	ct = r.Header.Get("Content-Type")
	if ct == "" {
		ct = "-"
	} else {
		ct = strings.Split(ct, ";")[0]
		// MIME type parameters droped
	}
	p.rl.record(log)
	return
}

func (p *proxy) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.px.ServeHTTP(w, r)
}

package pmproxy

import (
	g "github.com/elazarl/goproxy"
	. "net/http"
	"strings"
	"time"
)

type Proxy struct {
	qa *QAdm
	px *g.ProxyHttpServer
	rl *RLog
}

func (p *Proxy) Init(qa *QAdm, rl *RLog) {
	p.px, p.qa, p.rl = g.NewProxyHttpServer(), qa, rl
	p.px.OnRequest().DoFunc(restrictAccess)
	p.px.OnResponse().DoFunc(updateConsumption)
}

func (p *Proxy) restrictAccess(r *Request,
	c *g.ProxyCtx) (x *Request, y *Response) {
	ud := new(usrDt)
	ud.cf, x = p.qa.CanReq(), r
	if cf < 0 {
		y = g.NewResponse(r, g.ContentTypeText, StatusForbidden,
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

func (p *Proxy) updateConsumption(r *Response,
	c *g.ProxyCtx) (x *Response) {
	// { c.UserData ≠ nil ∧ c.UserData has type *usrDt }
	var ud *usrDt
	var cl float32
	x, ud, cl = r, c.UserData.(*usrDt), float32(r.ContentLength)
	p.qa.AddCons(r.Request.RemoteAddr, uint64(ud.cf*cl))
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
	p.rl.Record(log)
	return
}

func (p *Proxy) ServeHTTP(w ResponseWriter, r *Request) {
	p.px.ServeHTTP(w, r)
}

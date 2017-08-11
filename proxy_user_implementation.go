package main

import (
	"fmt"
	"io"
)

type PrxIm struct {
	SessionManager
	QuotaUser
	w io.Writer
}

func NewProxyIm(sm SessionManager, q QuotaUser,
	w io.Writer) (p *PrxIm) {
	p = &PrxIm{sm, q, w}
	return
}

func (p *PrxIm) CanReq(user Name, addr IP) (b bool) {
	b = p.Logged(user, addr) &&
		p.GetUserConsumption(user) < p.GetUserQuota(user)
	return
}

const (
	//TODO write according squid log format
	logFormat = "%s"
)

func (p *PrxIm) LogRes(user Name, addr IP, meth, uri,
	proto string, sc int, sz uint64, dt time.Time) (e error) {
	_, e = fmt.Fprintf(p.w, logFormat, user, addr, meth, uri,
		proto, sc, sz, dt.String())
	return
}

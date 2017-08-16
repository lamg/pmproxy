package main

import (
	"fmt"
	"io"
	"time"
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
		p.GetUserConsumption(addr) < p.GetUserQuota(addr)
	return
}

const (
	// timestamp delay IP src status size method uri user
	logFormat = "%d.%d %d %s TCP_TUNNEL/%d %d %s HIER_DIRECT/%s -"
)

func (p *PrxIm) LogRes(dest, addr IP, meth, uri, proto string,
	sc int, sz uint64, dt time.Time) (e error) {
	_, e = fmt.Fprintf(p.w, logFormat, dt.Unix(), dt.UnixNano(),
		delay, src, sc, sz, meth, uri, user, dest)
	return
}

// "%{INT:timestamp}.%{INT}\s*%{NUMBER:request_msec:float}
// %{IPORHOST:src_ip}
// %{WORD:cache_result}/%{NUMBER:response_status:int}
// %{NUMBER:response_size:int} %{WORD:http_method}
// (%{URIPROTO:http_proto}://)?%{IPORHOST:dst_host}
//   (?::%{POSINT:port})?(?:%{DATA:uri_param})?
// %{USERNAME:cache_user}
// %{WORD:request_route}/(%{IPORHOST:forwarded_to}|-)
// %{GREEDYDATA:content_type}"

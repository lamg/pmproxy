package pmproxy

import (
	"encoding/json"
	rt "github.com/lamg/rtimespan"
	"net"
	h "net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

type ConSpec struct {
	Cf    int
	Iface string
	Proxy *url.URL
	Quota uint64
	Cons  *uint64
	Rt    *Rate
}

type Rate struct {
	Bytes     uint64
	TimeLapse time.Duration
}

type Det interface {
	Det(*h.Request, time.time, *ConSpec) bool
}

type ResDet struct {
	// when unit is true Det returns the match of a predicate
	// when unit is false Det returns the match of no predicate
	Unit bool
	Rs   *rt.RSpan
	Rg   *net.IPNet
	Ur   *regexp.Regexp
	Gm   *GrpMtch
	Um   *UsrMtch
	// partial connection specification
	Pr *ConSpec
	Cs *CMng
	Qm *QMng
	Dm *DMng
}

func (d *ResDet) Det(r *h.Request, t time.Time,
	f *ConSpec) (b bool) {
	ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	// ip != ""
	bs := []bool{
		d.Rs != nil && d.Rs.ContainsTime(t),
		d.Rg != nil && contIP(d.Rg, ip),
		d.Ud != nil && d.Um.Match(ip),
		d.Ur != nil && d.Ur.MatchString(r.URL.HostName()),
		d.Gm != nil && d.Gm.Match(ip),
	}
	i := 0
	for i != len(bs) && !bs[i] {
		i = i + 1
	}
	b = (i != len(bs)) == d.Unit
	if b {
		addRes(f, d.Pr, d.Qm, d.Cs, d.Dm, ip)
	}
	return
}

func contIP(r *net.IPNet, ip string) (b bool) {
	// ip is a string with IP format
	ni := net.ParseIP(ip)
	b = r.Contains(ni)
	return
}

func addRes(s0, s1 *ConSpec, q *QMng, c *CMng, d *DMng, ip string) {
	s0.Cf = s1.Cf
	if s1.Iface != "" {
		s0.Iface = s1.Iface
	}
	if s1.Proxy != nil {
		s0.Proxy = s1.Proxy
	}
	if q != nil {
		s0.Quota = q.Get(ip)
	}
	if c != nil {
		s0.Cons = c.Get(ip)
	}
	if d != nil {
		s0.Rt = d.Get(ip)
	}
	return
}

type SqDet struct {
	// when unit is true Det returns for all Ds Det is true
	// when unit is false Det returns exists Det true in Ds
	Unit bool
	Ds   []Det
}

func (d *SqDet) Det(r *h.Request, t time.Time,
	c *ConSpec) (b bool) {
	i := 0
	for i != len(d.Ds) && (d.Ds[i].Det(r, t, c) == d.Unt) {
		i = i + 1
	}
	b = i != len(d.Ds)
	return
}

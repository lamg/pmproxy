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

type ResDet struct {
	// partial connection specification
	Pr *ConSpec
	Rs *rt.RSpan
	Rg *net.IPNet
	Ud *SMng
	Ur *regexp.Regexp
	Gm *GrpMtch
	Cs *CMng
	Qm *QMng
}

func (d *ResDet) Det(r *h.Request, t time.Time,
	f *ConSpec) {
	ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	// ip != ""
	bs := []bool{
		d.Rs != nil && d.Rs.ContainsTime(t),
		d.Rg != nil && contIP(d.Rg, ip),
		d.Ud != nil && dictHas(d.Ud.su, ip),
		d.Ur != nil && d.Ur.MatchString(r.URL.HostName()),
		d.Gm != nil && d.Gm.Match(ip),
	}
	i := 0
	for i != len(bs) && !bs[i] {
		i = i + 1
	}
	if i != len(bs) {
		addRes(f, d.Pr)
	}
	return
}

func contIP(r *net.IPNet, ip string) (b bool) {
	// ip is a string with IP format
	ni := net.ParseIP(ip)
	b = r.Contains(ni)
	return
}

func dictHas(m *sync.Map, s string) (b bool) {
	// m is a dictionary with only strings as keys
	_, b = m.Load(s)
	return
}

func addRes(s0, s1 *ConSpec) {
	if s1.Cf != 1 {
		s0.Cf = s1.Cf
	}
	if s1.Cons != nil {
		v, ok := d.Cs.Cons.Load(ip)
		var u uint64
		if ok {
			u = v.(uint64)
		}
		f.Cons = &v
	}
	return
}

type CfDet struct {
	Cf int     `json:"cf"`
	Rd *ResDet `json:"det"`
}

type StringDet struct {
	Str string  `json:"str"`
	Rd  *ResDet `json:"det"`
}

type ProxyDet struct {
	Proxy *url.URL
	Rd    *ResDet
}

type proxyJM struct {
	Proxy string  `json:"proxy"`
	Rd    *ResDet `json:"det"`
}

func (p *ProxyDet) MarshalJSON() (bs []byte, e error) {
	pj := &proxyJM{
		Proxy: p.Proxy.String(),
		Rd:    p.ResDet,
	}
	bs, e = json.Marshal(pj)
	return
}

func (p *ProxyDet) UnmarshalJSON(bs []byte) (e error) {
	pj := new(proxyJM)
	e = json.Unmarshal(bs, pj)
	if e == nil {
		p.Rd = pj.ResDet
		p.Proxy, e = url.Parse(pj.Proxy)
	}
	return
}

type ThrDet struct {
	Thr float64 `json:"thr"`
	Rd  *ResDet `json:"det"`
}

type ConsDet struct {
	Cons *uint64
	CsM  *CMng
	Usr  *StringDet
}

func (c *ConsDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = c.Usr.Det(r, d)
	if ok && e == nil {
		c.Cons, ok = c.CsM.Get(c.Usr.Str)
	}
	return
}

type ConSpec struct {
	Proxy    *url.URL
	Iface    string
	Cf       int
	Throttle float64
	Quota    uint64
	Cons     *uint64
}

type AndDet struct {
	Ds []ResDet
}

func (d *AndDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, i := true, 0
	for b && e == nil && i != len(d.Ds) {
		b, e = d.Ds[i].Det(r, t)
		if b && e == nil {
			i = i + 1
		}
	}
	return
}

type OrDet struct {
	Ds []ResDet
}

func (d *OrDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, i := false, 0
	for !b && i != len(d.Ds) {
		b, e = d.Ds[i].Det(r, t)
		if !b {
			i = i + 1
		}
	}
	return
}

type NegDet struct {
	ResDet
}

func (d *NegDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, e = d.ResDet.Det()
	b = !b
	return
}

type RgIPDt *net.IPNet

func (g RgIPDt) Det(r *h.Request, t time.Time) (b bool, e error) {

	return
}

type TSpDt *rt.RSpan

func (p TSpDt) Det(r *h.Request, t time.Time) (b bool, e error) {
	b = p.ContainsTime(t)
	return
}

type GrpDB interface {
	Get(string) ([]string, error)
}

type GrpDt struct {
	Gr    string
	UsrDt *StringDet
	GDB   GrpDB
}

func (p *GrpDt) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, e = p.UsrDt.Det(r, t)
	var gs []string
	if b {
		gs, e = p.GDB.Get(p.UsrDt.Str)
	}
	i := 0
	for b && e == nil && i != len(gs) {
		b = gs[i] == p.Gr
		if !b {
			i = i + 1
		}
	}
	return
}

package pmproxy

import (
	"encoding/json"
	rt "github.com/lamg/rtimespan"
	"net"
	h "net/http"
	"net/url"
	"regexp"
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
	Det(*h.Request, time.Time, *ConSpec) bool
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
	Dm *DMng
}

type rdJ struct {
	Unit bool      `json:"unit"`
	Rs   *rt.RSpan `json:"rs"`
	Rg   string    `json:"rg"`
	Ur   string    `json:"ur"`
	Gm   *GrpMtch  `json:"gm"`
	Um   *UsrMtch  `json:"um"`

	Pr *ConSpec `json:"pr"`
}

func (d *ResDet) MarshalJSON() (bs []byte, e error) {
	j := &rdJ{
		Unit: d.Unit,
		Rs:   d.Rs,
		Rg:   d.Rg,
		Ur:   d.Ur,
		Gm:   d.Gm,
		Um:   d.Um,
		Pr:   d.Pr,
	}
	bs, e = json.Marshal(j)
	return
}

func (d *ResDet) UnmarshalJSON(bs []byte) (e error) {
	v := new(rdJ)
	e = json.Unmarshal(bs, v)
	if e == nil {
		d.Unit, d.Rs, d.Gm, d.Um, d.Pr = v.Unit, v.Rs, v.Gm, v.Um,
			v.Pr
		_, d.Rg, e = net.ParseCIDR(v.Rg)
	}
	if e == nil {
		d.Ur, e = regexp.Compile(v.Ur)
	}
	return
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
	Unit bool  `json:"unit"`
	Ds   []Det `json:"ds"`
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

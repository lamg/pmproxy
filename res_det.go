package pmproxy

import (
	"encoding/json"
	rt "github.com/lamg/rtimespan"
	"net"
	h "net/http"
	"regexp"
	"time"
)

type ConSpec struct {
	// Consumption coeficient
	Cf float32
	// Assigned coeficient (Cf) has priority
	CfHPr bool
	Span  *rt.RSpan
	Iface string
	Proxy string
	Quota uint64
	Cons  *ConsAdd
	Rt    *Rate
	Cl    *CLMng
	Test  bool
}

func (s *ConSpec) Valid() (b bool) {
	b = s.Cf >= 0 && (s.Iface != "" || s.Proxy != "" || s.Test) &&
		s.Cons != nil && s.Rt != nil
	return
}

type Rate struct {
	Bytes     uint64
	TimeLapse time.Duration
	CurrConn  *uint64
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
	Cl *CLMng
}

type rdJ struct {
	Unit bool      `json:"unit"`
	Rs   *rt.RSpan `json:"rs"`
	Rg   string    `json:"rg"`
	Ur   string    `json:"ur"`
	Gm   *GrpMtch  `json:"gm"`
	Um   *UsrMtch  `json:"um"`

	Pr *ConSpec `json:"pr"`
	// consumption manager (CMng) reference
	Cs string `json:"cs"`
	// delay manager (DMng) reference
	Dm string `json:"dm"`
	// connection limit manager (CLMng) reference
	Cl string `json:"cl"`
}

func (d *ResDet) MarshalJSON() (bs []byte, e error) {
	j := &rdJ{
		Unit: d.Unit,
		Rs:   d.Rs,
		Rg:   d.Rg.String(),
		Ur:   d.Ur.String(),
		Gm:   d.Gm,
		Um:   d.Um,
		Pr:   d.Pr,
		Cs:   d.Cs.Name,
		Dm:   d.Dm.Name,
		Cl:   d.Cl.Name,
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
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	// ip != ""
	bs := []bool{
		d.Rs != nil && d.Rs.ContainsTime(t),
		d.Rg != nil && contIP(d.Rg, ip),
		d.Um != nil && d.Um.Match(ip),
		d.Ur != nil && d.Ur.MatchString(r.URL.Hostname()),
		d.Gm != nil && d.Gm.Match(ip),
	}
	i := 0
	for i != len(bs) && !bs[i] {
		i = i + 1
	}
	b = (i != len(bs)) == d.Unit
	if b {
		// ConsAdd right place to be initialized
		var ca *ConsAdd
		if d.Cs != nil && d.Um != nil {

			user, ok := d.Um.Sm.MatchUsr(ip)
			// MatchUsr error
			if ok {
				ca = d.Cs.Adder(user)
			}
		}
		addRes(f, d.Pr, ca, d.Dm)
	}
	return
}

func contIP(r *net.IPNet, ip string) (b bool) {
	// ip is a string with IP format
	ni := net.ParseIP(ip)
	b = r.Contains(ni)
	return
}

func addRes(s0, s1 *ConSpec, c *ConsAdd, d *DMng) {
	if s1 != nil {
		if !s0.CfHPr {
			s0.Cf = s1.Cf
		}
		if s1.Iface != "" {
			s0.Iface = s1.Iface
		}
		if s1.Proxy != "" {
			s0.Proxy = s1.Proxy
		}
		s0.Quota = s0.Quota + s1.Quota
		if c != nil {
			s0.Cons = c
		}
		if d != nil {
			s0.Rt = d.NewConnRate()
		}
		if s1.Cl != nil {
			s0.Cl = s1.Cl
		}
	}
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
	for i != len(d.Ds) && (d.Ds[i].Det(r, t, c) == d.Unit) {
		i = i + 1
	}
	b = (i == len(d.Ds)) == d.Unit
	return
}

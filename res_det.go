package pmproxy

import (
	"encoding/json"
	"net"
	h "net/http"
	"regexp"
	"time"

	rt "github.com/lamg/rtimespan"
)

// ConSpec contains the information for making a connection
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
	Dm    *DMng
	Cl    *CLMng
	User  string
}

// Valid returns whether the connection specification is valid
func (s *ConSpec) Valid() (b bool) {
	b = s.Cf >= 0 && (s.Iface != "" || s.Proxy != "") &&
		s.Cons != nil && s.Dm != nil
	return
}

// Rate is the connection rate representation
type Rate struct {
	Bytes     uint64
	TimeLapse time.Duration
}

// Det is a predicate for matching requests, which is useful
// for associating them with resources. It's implemented by
// ResDet and SqDet
type Det interface {
	Det(*h.Request, time.Time, *ConSpec) bool
}

// ResDet is the basic resource determinator
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
	// why not using repeat Pr.Dm and Dm, Pr.Cl and Dl
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

// MarshalJSON is the json.Marshaler implementation
func (d *ResDet) MarshalJSON() (bs []byte, e error) {
	rg, ur, cs, dm, cl := "", "", "", "", ""
	if d.Rg != nil {
		rg = d.Rg.String()
	}
	if d.Ur != nil {
		ur = d.Ur.String()
	}
	if d.Cs != nil {
		cs = d.Cs.Name
	}
	if d.Dm != nil {
		dm = d.Dm.Name
	}
	if d.Cl != nil {
		cl = d.Cl.Name
	}
	j := &rdJ{
		Unit: d.Unit,
		Rs:   d.Rs,
		Rg:   rg,
		Ur:   ur,
		Gm:   d.Gm,
		Um:   d.Um,
		Pr:   d.Pr,
		Cs:   cs,
		Dm:   dm,
		Cl:   cl,
	}
	bs, e = json.Marshal(j)
	return
}

// UnmarshalJSON is the json.Unmarshaler implementation
func (d *ResDet) UnmarshalJSON(bs []byte) (e error) {
	v := new(rdJ)
	e = json.Unmarshal(bs, v)
	if e == nil {
		d.Unit, d.Rs, d.Gm, d.Um, d.Pr = v.Unit, v.Rs, v.Gm, v.Um,
			v.Pr
		if v.Rg != "" {
			_, d.Rg, e = net.ParseCIDR(v.Rg)
		}
	}
	if e == nil && v.Ur != "" {
		d.Ur, e = regexp.Compile(v.Ur)
	}
	if v.Cl != "" {
		d.Cl = NewCLMng(v.Cl, 0)
	}
	if v.Cs != "" {
		d.Cs = NewCMng(v.Cs)
	}
	if v.Dm != "" {
		d.Dm = &DMng{
			Name: v.Dm,
		}
	}
	return
}

// Det is the Det implementation
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
				f.User = user
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
			s0.Cons = s1.Cons
		}
		if d != nil {
			s0.Dm = d
		}
		if s1.Cl != nil {
			s0.Cl = s1.Cl
		}
	}
}

// SqDet implements Det evalues a sequence of determinators.
// When SqDet.Unit is true it performs a for all, and when
// is false it performs an exists evaluation.
type SqDet struct {
	// when unit is true Det returns for all Ds Det is true
	// when unit is false Det returns exists Det true in Ds
	Unit bool      `json:"unit"`
	RDs  []*ResDet `json:"rds"`
	SDs  []*SqDet  `json:"sds"`
}

// Det is the Det implementation
func (d *SqDet) Det(r *h.Request, t time.Time,
	c *ConSpec) (b bool) {
	if d.RDs != nil {
		b = blsResDet(d.RDs, d.Unit, r, t, c)
	} else {
		b = blsSqDet(d.SDs, d.Unit, r, t, c)
	}
	return
}

func blsResDet(rs []*ResDet, unit bool, r *h.Request, t time.Time,
	c *ConSpec) (b bool) {
	i := 0
	for i != len(rs) && (rs[i].Det(r, t, c) == unit) {
		i = i + 1
	}
	b = (i == len(rs)) == unit
	return
}

func blsSqDet(ss []*SqDet, unit bool, r *h.Request, t time.Time,
	c *ConSpec) (b bool) {
	i := 0
	for i != len(ss) && (ss[i].Det(r, t, c) == unit) {
		i = i + 1
	}
	b = (i == len(ss)) == unit
	return
}
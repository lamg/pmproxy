package pmproxy

import (
	"encoding/json"
	rs "github.com/lamg/rtimespan"
	"net"
	h "net/http"
	"sort"
	"time"
)

// This file contains types used in res_det.go
// It contains types useful for getting the boolean
// value corresponding to a Cond instance.

// Cond is a condition for matching a request, time
// and user. A nil field matches all elements.
type Cond struct {
	// ip is contained by one of the *net.IPNet
	// in CIDR format
	Net []string `json:"net"`
	// time is contained by one of the *rs.RSpan
	Rs []*rs.RSpan `json:"rs"`
	// LDAP filter format string for the user
	LFlt string `json:"lFlt"`
	// usr is in Usrs
	Usrs []string `json:"usrs"`
	// request.URL.Hostname() is in ReqHost
	ReqHost []string `json:"reqHost"`
	// request.URL.Port() is in ReqPort
	ReqPort []string `json:"reqPort"`
	// constructed with values in Net, for determining
	// if an IP belongs to the following networks
	nt []*net.IPNet
}

func (c *Cond) UnmarshalJSON(p []byte) (e error) {
	e = json.Unmarshal(p, c)
	if e == nil {
		c.nt = make([]*net.IPNet, len(c.Net))
	}
	for i := 0; e == nil && i != len(c.Net); i++ {
		_, c.nt[i], e = net.ParseCIDR(c.Net[i])
	}
	return
}

// Bool implementation for Cond
type evCond struct {
	c   *Cond
	r   *h.Request
	t   time.Time
	ld  LdapFlt
	usr string
	e   *err
}

func (v *evCond) V() (y bool) {
	hs, _, _ := net.SplitHostPort(v.r.RemoteAddr)
	cs := []Bool{
		&netC{nt: v.c.nt, ip: net.ParseIP(hs)},
		&tmC{t: v.t, s: v.c.Rs},
		&ldBool{usr: v.usr, ldf: v.ld, e: v.e},
		&strSC{slc: v.c.Usrs, x: v.usr},
		&strSC{slc: v.c.ReqHost, x: v.r.URL.Hostname()},
		&strSC{slc: v.c.ReqPort, x: v.r.URL.Port()},
	}
	// each Bool in cs equivales to 'the test fails'
	// if no test fails, then all test are true.

	// since BoundedLinearSearch searches the first true,
	// and what I need is searching the first false (that
	// equivales, if that false is not found, to for all
	// test in cs no one fails.
	f, _ := BoundedLinearSearch(cs)
	// { ¬f ≡ all elements in cs no one fails }
	y = !f
	return
}

type err struct {
	e error
}

type ldBool struct {
	usr string
	ldf LdapFlt
	e   *err
}

func (l *ldBool) V() (y bool) {
	var ok bool
	ok, l.e.e = l.ldf.UserOK(l.usr)
	y = !ok || l.e.e != nil
	return
}

// Bool implementation for a []string
// tells whether a string slice contains a string
type strSC struct {
	// slc must be sorted in non-decreasing order
	slc []string
	x   string
}

func (s *strSC) V() (y bool) {
	ok := s.slc != nil
	if y {
		i := sort.SearchStrings(s.slc, s.x)
		ok = i != len(s.slc) && s.slc[i] == s.x
	}
	// { ok ≡ s.slc = nil ∨ s.x exists in s.slc }
	y = !ok
	return
}

// Bool implementation for a []*net.IPNet
type netC struct {
	nt []*net.IPNet
	ip net.IP
}

func (n *netC) V() (y bool) {
	ni := make([]Bool, len(n.nt))
	for i, j := range n.nt {
		ni[i] = &bIPNet{nt: j, ip: n.ip}
	}
	ok, _ := BoundedLinearSearch(ni)
	y = !ok
	return
}

// Bool implementation for *net.IPNet
type bIPNet struct {
	nt *net.IPNet
	ip net.IP
}

func (b *bIPNet) V() (y bool) {
	y = b.nt.Contains(b.ip)
	return
}

// Bool implementation for []*rs.RSpan
type tmC struct {
	s []*rs.RSpan
	t time.Time
}

func (m *tmC) V() (y bool) {
	bs := make([]Bool, len(m.s))
	for i, j := range m.s {
		bs[i] = &rs.BRSpan{S: j, T: m.t}
	}
	ok, _ := BoundedLinearSearch(bs)
	y = !ok
	return
}

type Bool interface {
	V() bool
}

// Searchs the first true if it exists
// { len(a) != 0 }
func BoundedLinearSearch(a []Bool) (f bool, i int) {
	f, i = a[0].V(), 0
	for !f && i != len(a) {
		f, i = a[i].V(), i+1
	}
	// f ≡ a[i].V() ≡ i ≠ len(a)
	return
}

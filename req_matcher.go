package pmproxy

import (
	"encoding/json"
	"net"
	"regexp"
)

// IPRangeM is an IP range matcher, with a time
// interval/rule
type IPRangeM struct {
	// convert IP to byte slice and compare
	nt *net.IPNet
	// IPRanges is the []string representation of Filter
	IPRange string `json:"ipRange"`
}

// UnmarshalJSON is the json.Unmarshal implementation
func (ir *IPRangeM) UnmarshalJSON(p []byte) (e error) {
	e = json.Unmarshal(p, ir)
	if e == nil {
		_, ir.nt, e = net.ParseCIDR(ir.IPRange)
	}
	return
}

// Eval is the Predicate implementation
func (ir *IPRangeM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	if y {
		ips, _, e := net.SplitHostPort(u.rc.rAddr)
		var ip net.IP
		if e == nil {
			ip = net.ParseIP(ips)
		}
		y = ip != nil && ir.nt.Contains(ip)
	}
	return
}

// PortM matches the url port
type PortM string

// Eval is the Predicate implementation
func (m PortM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	y = y && string(m) == u.rc.url.Port()
	return
}

// LDAPGroupM matches the user's LDAP group
type LDAPGroupM string

// Eval is the Predicate implementation
func (m LDAPGroupM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	y = y && string(m) == u.usr.QuotaGroup
	return
}

// URLM matches by URL
type URLM struct {
	hostR  *regexp.Regexp
	HostRS string `json:"hostRS"`
}

// UnmarshalJSON is the json.UnmarshalJSON implementation
func (m *URLM) UnmarshalJSON(p []byte) (e error) {
	e = json.Unmarshal(p, m)
	if e == nil {
		m.hostR, e = regexp.Compile(m.HostRS)
	}
	return
}

// Eval is the Predicate implementation
func (m *URLM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	y = y && m.hostR.MatchString(u.rc.url.Host)
	return
}

// UserM matches by user name
type UserM string

// Eval is the Predicate implementation
func (m UserM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	y = y && string(m) == u.usr.UserName
	return
}

// ContM matches by content type
type ContM string

// Eval is the Predicate implementation
func (m ContM) Eval(v interface{}) (y bool) {
	var u *usrRC
	u, y = v.(*usrRC)
	y = y && string(m) == u.rc.contTpe
	return
}

// ForAllExists equivales to for all []Predicate
// exists one true for v in each one. n is the index
// in each []Predicate of the first Predicate true
// for v.
func ForAllExists(r [][]Predicate,
	v interface{}) (y bool, n []int) {
	var sp []Predicate
	sp = make([]Predicate, len(r))
	for i, j := range r {
		sp[i] = &SPred{RMts: j}
	}
	x, ln := BLS(sp, v)
	// { x == an element of sp returned false for v
	//   and ln is its index }
	n = make([]int, ln)
	for i := 0; i != ln; i++ {
		n[i] = sp[i].(*SPred).i
	}
	y = !x
	// { y == all elements of sp returned true for v }
	return
}

// SPred is a predicate over a []Predicate
// which equivales to all predicates false
// for the supplied value
type SPred struct {
	// Requests matchers
	RMts []Predicate `json:"rMts"`
	i    int
}

// Eval is the Predicate implementation
func (p *SPred) Eval(v interface{}) (y bool) {
	var r bool
	r, p.i = BLS(p.RMts, v)
	y = !r
	return
}

// Predicate abstracts all predicates
type Predicate interface {
	Eval(interface{}) bool
}

// BLS is the Bounded Linear Search algorithm, using
// Matcher.Match as predicate
func BLS(ms []Predicate, u interface{}) (b bool, i int) {
	b, i = false, 0
	// { (b = (exists i: 0<=i<len(ms): ms[i].Match(u)) =
	//	 i!=len(ms)) and 0<=i<=len(ms) }
	for !b && i != len(ms) {
		b = ms[i].Eval(u)
		if !b {
			i = i + 1
		}
	}
	return
}

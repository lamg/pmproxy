package pmproxy

import (
	"net"
	"regexp"

	rt "github.com/lamg/rtimespan"
)

// IPRangeM is an IP range matcher, with a time
// interval/rule
type IPRangeM struct {
	// convert IP to byte slice and compare
	Start, End net.IP
	Span       *rt.RSpan
}

// LDAPGroupM matches the user's LDAP group
type LDAPGroupM struct {
	Name string
	Span *rt.RSpan
}

// URLM matches by URL
type URLM struct {
	HostR *regexp.Regexp
	Ports []int
	Span  *rt.RSpan
}

// UsersM matches by user name
type UsersM struct {
	Users []string
	Span  *rt.RSpan
}

// ContM matches by content type
type ContM struct {
	MIMET []string
	Span  *rt.RSpan
}

// ReqMatcher matches requests
type ReqMatcher struct {
}

// Match does de actual matching
func (r *ReqMatcher) Match(u *usrRC) (y bool) {
	// TODO
	return
}

// Matcher is an interface for matching *usrRC
type Matcher interface {
	Match(*usrRC) bool
}

// BLS is the Bounded Linear Search algorithm, using
// Matcher.Match as predicate
func BLS(ms []Matcher, u *usrRC) (b bool,
	i int) {
	b, i = false, 0
	// { (b = (exists i: 0<=i<len(ms): ms[i].Match(u)) =
	//	 i!=len(ms)) and 0<=i<=len(ms) }
	for !b && i != len(ms) {
		b = ms[i].Match(u)
		if !b {
			i = i + 1
		}
	}
	return
}

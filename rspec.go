package pmproxy

import (
	"fmt"
	"net"
	h "net/http"
	"regexp"
	"time"

	rt "github.com/lamg/rtimespan"
)

type simpleRSpec struct {
	rules [][]Rule
}

type Rule struct {
	Unit bool
	Span *rt.RSpan
	URLM *regexp.Regexp
	IPM  IPMatcher
	Spec *Spec
}

type IPMatcher interface {
	Match(string) bool
}

func (s *simpleRSpec) Spec(t time.Time,
	r *h.Request) (n *Spec, e error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, j := range s.rules {
		b, k := true, 0
		for b && k != len(j) {
			b = j[k].Unit == ((j[k].IPM == nil || j[k].IPM.Match(ip)) &&
				(j[k].Span == nil || j[k].Span.ContainsTime(t)) &&
				(j[k].URLM == nil || j[k].URLM.MatchString(r.RequestURI)))
			k = k + 1
		}
		// b = all rules in j match the parameters
		if b {
			n = new(Spec)
			// add Spec to n
			sn := j[k].Spec
			if sn.Bandwidth != nil {
				n.Bandwidth = sn.Bandwidth
			}
			if sn.Cr != nil {
				n.Cr = sn.Cr
			}
			if sn.Iface != "" {
				n.Iface = sn.Iface
			}
			if sn.ProxyURL != "" {
				n.ProxyURL = sn.ProxyURL
			}
			if j[k].Span != nil {
				n.Span = j[k].Span
			}
		}
	}
	if n.Bandwidth == nil || n.Cr == nil ||
		((n.Iface == "") == (n.ProxyURL == "")) {
		e = InvalidSpec()
	}
	return
}

func InvalidSpec() (e error) {
	e = fmt.Errorf("Invalid Spec")
	return
}

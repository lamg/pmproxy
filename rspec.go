package pmproxy

import (
	"fmt"
	"net"
	h "net/http"
	"regexp"
	"time"
)

type simpleRSpec struct {
	rules [][]Rule
}

type Rule struct {
	Unit bool
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
				(j[k].URLM == nil || j[k].URLM.MatchString(r.RequestURI)))
			k = k + 1
		}
		// b = all rules in j match the parameters
		if b {
			n = new(Spec)
			// add Spec to n
			sn := j[k].Spec
			if sn.Cr != nil {
				n.Cr = append(n.Cr, sn.Cr...)
			}
			if sn.Iface != "" {
				n.Iface = sn.Iface
			}
			if sn.ProxyURL != "" {
				n.ProxyURL = sn.ProxyURL
			}
		}
	}
	if len(n.Cr) == 0 || ((n.Iface == "") == (n.ProxyURL == "")) {
		e = InvalidSpec()
	}
	return
}

func InvalidSpec() (e error) {
	e = fmt.Errorf("Invalid Spec")
	return
}

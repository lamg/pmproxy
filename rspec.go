package pmproxy

import (
	"encoding/json"
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
	URLM *regexp.Regexp
	span *rt.RSpan
	IPM  IPMatcher
	Spec *Spec
}

func (r *Rule) MarshalJSON() (bs []byte, e error) {
	jr := &JRule{
		Unit: r.Unit,
		URLM: r.URLM.String(),
		Span: r.span,
		IPM:  r.IPM.Name(),
		Spec: &JSpec{
			Iface:    r.Spec.Iface,
			ProxyURL: r.Spec.ProxyURL,
			ConsR:    make([]string, len(r.Spec.Cr)),
		},
	}
	for i, j := range r.Spec.Cr {
		jr.Spec.ConsR[i] = j.Name()
	}
	bs, e = json.Marshal(jr)
	return
}

type JRule struct {
	Unit bool      `json:"unit"`
	URLM string    `json:"urlm"`
	Span *rt.RSpan `json:"span"`
	IPM  string    `json:"ipm"`
	Spec *JSpec    `json:"spec"`
}

type JSpec struct {
	Iface    string   `json:"iface"`
	ProxyURL string   `json:"proxyURL"`
	ConsR    []string `json:"consR"`
}

type IPMatcher interface {
	Name() string
	Match(string) bool
}

func (s *simpleRSpec) Spec(t time.Time,
	r *h.Request) (n *Spec, e error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, j := range s.rules {
		b, k := true, 0
		for b && k != len(j) {
			b = j[k].Unit == ((j[k].IPM == nil || j[k].IPM.Match(ip)) &&
				(j[k].URLM == nil || j[k].URLM.MatchString(r.RequestURI)) &&
				(j[k].span == nil || j[k].span.ContainsTime(t)))
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

func InvalidArgs(v interface{}) (e error) {
	e = fmt.Errorf("Invalid arguments %v", v)
	return
}

func (s *simpleRSpec) remove(args []int) (e error) {
	argc := len(args)
	if argc < len(s.rules) {
		if argc == 1 {
			s.rules = append(s.rules[:args[0]],
				s.rules[args[0]+1:]...)
			// no index out of range
		} else if argc == 2 {
			s.rules[args[0]] = append(s.rules[args[0]][:args[1]],
				s.rules[args[0]][args[1]+1:]...)
		} else {
			e = InvalidArgs(args)
		}
	} else {
		e = IndexOutOfRange(argc, len(s.rules))
	}
	return
}

func (s *simpleRSpec) add(pos []int, rule *Rule) (e error) {
	if len(pos) == 1 {
		if pos[0] == -1 {
			s.rules = append(s.rules, []Rule{*rule})
		} else if pos[0] >= 0 && pos[0] < len(s.rules) {
			s.rules = append(s.rules[:pos[0]],
				append([][]Rule{{*rule}},
					s.rules[pos[0]:]...)...)
		} else {
			e = IndexOutOfRange(pos[0], len(s.rules))
		}
	} else if len(pos) == 2 {
		if 0 <= pos[0] && pos[0] < len(s.rules) {
			rules := s.rules[pos[0]]
			if pos[1] == -1 {
				s.rules[pos[0]] = append(rules, *rule)
			} else if 0 <= pos[1] &&
				pos[1] < len(rules) {
				s.rules[pos[0]] = append(rules[:pos[1]],
					append([]Rule{*rule}, rules[pos[1]:]...)...)
			} else {
				e = IndexOutOfRange(pos[1], len(rules))
			}
		}
	} else {
		e = InvalidArgs(pos)
	}
	return
}

func (s *simpleRSpec) show() (r string, e error) {
	var bs []byte
	bs, e = json.Marshal(s.rules)
	if e == nil {
		r = string(bs)
	}
	return
}

func IndexOutOfRange(i, n int) (e error) {
	e = fmt.Errorf("Index %d out of range %d", i, n)
	return
}

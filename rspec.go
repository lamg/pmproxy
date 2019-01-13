package pmproxy

import (
	"encoding/json"
	"fmt"
	"net"
	h "net/http"
	"net/url"
	"regexp"
	"time"

	rt "github.com/lamg/rtimespan"
)

type rspec struct {
	rules [][]rule
	ipm   func(string) (matcher, bool)
}

type rule struct {
	Unit bool      `json:"unit"`
	URLM string    `json:"urlm"`
	Span *rt.RSpan `json:"span"`
	IPM  string    `json:"ipm"`
	Spec *spec     `json:"spec"`
}

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	ConsR    []string `json:"consR"`
}

func (s *spec) init() (e error) {
	s.proxyURL, e = url.Parse(s.ProxyURL)
	return
}

func (s *rspec) spec(t time.Time,
	r *h.Request) (n *spec, e error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	inf := func(l int) {
		j := s.rules[l]
		ib := func(i int) (b bool) {
			ipm, ok := s.ipm(j[i].IPM)
			b = (j[i].unit == (!ok || ipm.Match(ip))) &&
				(j[i].urlM == nil ||
					j[i].urlM.MatchString(r.RequestURI)) &&
				(j[i].span == nil || j[i].span.ContainsTime(t))
			return
		}
		b, k := bLnSrch(ib, len(j))
		// b = all rules in j match the parameters
		if b {
			n = new(spec)
			// add Spec to n
			sn := j[k].spec
			if sn.Cr != nil {
				n.Cr = append(n.Cr, sn.Cr...)
			}
			if sn.Iface != "" {
				n.Iface = sn.Iface
			}
			if sn.ProxyURL != nil {
				n.ProxyURL = sn.ProxyURL
			}
		}
	}
	forall(inf, len(s.rules))
	if len(n.Cr) == 0 ||
		((n.Iface == "") == (n.ProxyURL == nil)) {
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

func (s *rspec) exec(c *AdmCmd) (r string, e error) {
	switch c.Cmd {
	case "add-rule":
		e = rl.spec.init()
		if e == nil {
			e = c.rspec.add(cmd.Pos, rl)
		}
	case "del-rule":
		e = c.rspec.delete(cmd.Pos)
	case "show-rules":
		r, e = c.rspec.show()
	}
	return
}

func (s *rspec) delete(args []int) (e error) {
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

func (s *rspec) add(pos []int, rl *rule) (e error) {
	if len(pos) == 1 {
		if pos[0] == -1 {
			s.rules = append(s.rules, []rule{*rl})
		} else if pos[0] >= 0 && pos[0] < len(s.rules) {
			s.rules = append(s.rules[:pos[0]],
				append([][]rule{{*rl}},
					s.rules[pos[0]:]...)...)
		} else {
			e = IndexOutOfRange(pos[0], len(s.rules))
		}
	} else if len(pos) == 2 {
		if 0 <= pos[0] && pos[0] < len(s.rules) {
			rules := s.rules[pos[0]]
			if pos[1] == -1 {
				s.rules[pos[0]] = append(rules, *rl)
			} else if 0 <= pos[1] &&
				pos[1] < len(rules) {
				s.rules[pos[0]] = append(rules[:pos[1]],
					append([]rule{*rl}, rules[pos[1]:]...)...)
			} else {
				e = IndexOutOfRange(pos[1], len(rules))
			}
		}
	} else {
		e = InvalidArgs(pos)
	}
	return
}

func (s *rspec) show() (r string, e error) {
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

func (s *rspec) manager() (m *manager) {
	name := "rules"
	m = &manager{
		name: name,
		tỹpe: name,
		adm:  s.exec,
		toMap: func() (mp map[string]interface{}) {
			// TODO
			return
		},
	}
	return
}

package pmproxy

import (
	"encoding/json"
	"fmt"
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/cast"
	"net"
	"regexp"
	"time"
)

type rspec struct {
	rules [][]rule
	ipm   nameMatcher
}

type nameMatcher func(string) (matcher, bool)

const (
	unitK = "unit"
	urlmK = "urlm"
	ipmK  = "ipm"
	specK = "spec"
	spanK = "span"
	posK  = "pos"
)

type rule struct {
	Unit bool   `json:"unit"`
	URLM string `json:"urlm"`
	urlm *regexp.Regexp
	Span *rt.RSpan `json:"span"`
	IPM  string    `json:"ipm"`
	Spec *spec     `json:"spec"`
}

func (r *rule) init() (e error) {
	r.urlm, e = regexp.Compile(r.URLM)
	if e == nil {
		e = r.Spec.init()
	}
	return
}

func (s *rspec) spec(t time.Time, method, url,
	rAddr string) (n *spec, e error) {
	ip, _, _ := net.SplitHostPort(rAddr)
	inf := func(l int) {
		j := s.rules[l]
		ib := func(i int) (b bool) {
			ipm, ok := s.ipm(j[i].IPM)
			b = (j[i].Unit == (!ok || ipm(ip))) &&
				(j[i].urlm == nil ||
					j[i].urlm.MatchString(url)) &&
				(j[i].Span == nil || j[i].Span.ContainsTime(t))
			return
		}
		b, k := bLnSrch(ib, len(j))
		// b = all rules in j match the parameters
		if b {
			n = new(spec)
			// add Spec to n
			sn := j[k].Spec
			if sn.ConsR != nil {
				n.ConsR = append(n.ConsR, sn.ConsR...)
			}
			if sn.Iface != "" {
				n.Iface = sn.Iface
			}
			if sn.proxyURL != nil {
				n.proxyURL = sn.proxyURL
			}
		}
	}
	forall(inf, len(s.rules))
	if len(n.ConsR) == 0 ||
		((n.Iface == "") == (n.proxyURL == nil)) {
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

func (s *rspec) admin(c *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	cs = []cmdProp{
		{
			cmd: add,
			f: func() {
				e := c.Rule.init()
				if e == nil {
					e = s.add(c.Pos, c.Rule)
				}
				fe(e)
			},
		},
		{
			cmd: del,
			f: func() {
				fe(s.delete(c.Pos))
			},
		},
		{
			cmd: show,
			f: func() {
				bs, e := json.Marshal(s.rules)
				fb(bs)
				fe(e)
			},
		},
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

func IndexOutOfRange(i, n int) (e error) {
	e = fmt.Errorf("Index %d out of range %d", i, n)
	return
}

func (s *rspec) toSer() (i interface{}) {
	mp := make([]map[string]interface{}, 0)
	inf := func(i int) {
		inf0 := func(j int) {
			rl := s.rules[i][j]
			// TODO careful with nil references
			rmap := map[string]interface{}{
				unitK: rl.Unit,
				posK:  i,
				urlmK: rl.URLM,
				ipmK:  rl.IPM,
				spanK: toSerSpan(rl.Span),
				specK: rl.Spec.toSer(),
			}
			mp = append(mp, rmap)
		}
		forall(inf0, len(s.rules[i]))
	}
	forall(inf, len(s.rules))
	i = mp
	return
}

func (r *rspec) fromMapIKF(fe ferr) (f fikf) {
	f = func(n int) (kf []kFuncI) {
		rl := new(rule)
		kf = []kFuncI{
			{
				urlmK,
				func(i interface{}) {
					rl.URLM = stringE(i, fe)
					e := rl.init()
					fe(e)
				},
			},
			{
				ipmK,
				func(i interface{}) {
					rl.IPM = stringE(i, fe)
				},
			},
			{
				unitK,
				func(i interface{}) {
					rl.Unit = boolE(i, fe)
				},
			},
			{
				spanK,
				func(i interface{}) {
					rl.Span = new(rt.RSpan)
				},
			},
			{
				specK,
				func(i interface{}) {
					rl.Spec = new(spec)
				},
			},
		}
		kf = append(kf, fromMapKFSpan(rl.Span, fe)...)
		kf = append(kf, rl.Spec.fromMapKF(fe)...)
		kf = append(kf, kFuncI{
			posK,
			func(i interface{}) {
				pos, e := cast.ToIntE(i)
				if e == nil {
					if pos >= len(r.rules) {
						nl := pos - len(r.rules)
						nrl := make([][]rule, nl+1)
						r.rules = append(r.rules, nrl...)
					}
					r.rules[pos] = append(r.rules[pos], *rl)
				}
				fe(e)
			},
		},
		)
		return
	}
	return
}

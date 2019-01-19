package pmproxy

import (
	"encoding/json"
	"fmt"
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/cast"
	"net"
	h "net/http"
	"net/url"
	"regexp"
	"time"
)

type rspec struct {
	rules [][]rule
	ipm   nameMatcher
}

type nameMatcher func(string) (matcher, bool)

func newRspec(rm []map[string]interface{},
	ipm nameMatcher) (r *rspec, e error) {
	r = &rspec{
		ipm:   ipm,
		rules: make([][]rule, 0),
	}
	inf := func(i int) (ok bool, i int) {
		mp := rm[i]
		rl := new(rule)
		rl.Unit, e = cast.ToBool(mp[unitK])
		if e == nil {
			rl.URLM, e = cast.ToString(mp[urlmK])
		}
		if e == nil {
			rl.IPM, e = cast.ToString(mp[ipmK])
		}
		var pmp map[string]interface{} // map representing rt.RSpan
		if e == nil {
			pmp, e = cast.ToStringMap(mp[spanK])
		}
		var tms string
		if e == nil {
			rl.Span = new(rt.RSpan)
			tms, e = cast.ToString(pmp[starK])
		}
		if e == nil {
			rl.Span.Start, e = time.Parse(time.RFC3339, tms)
		}
		var drs string
		if e == nil {
			drs, e = cast.ToString(pmp[activeK])
		}
		if e == nil {
			rl.Span.Active, e = time.ParseDuration(drs)
		}
		var total string
		if e == nil {
			total, e = cast.ToString(pmp[totalK])
		}
		if e == nil {
			rl.Span.Total, e = time.ParseDuration(total)
		}
		if e == nil {
			rl.Span.Times, e = cast.ToInt(pmp[timesK])
		}
		if e == nil {
			rl.Span.Infinite, e = cast.ToBool(pmp[infiniteK])
		}
		if e == nil {
			rl.Span.AllTime, e = cast.ToBool(pmp[allTimeK])
		}
		var smp map[string]interface{} // map representinng spec
		if e == nil {
			smp, e = cast.ToStringMap(mp[specK])
		}
		if e == nil {
			rl.Spec = new(rt.Spec)
			rl.Spec.Iface, e = cast.ToString(smp[ifaceK])
		}
		if e == nil {
			rl.Spec.ProxyURL, e = cast.ToString(smp[proxyURLK])
		}
		if e == nil {
			rl.Spec.ConsR, e = cast.ToStringSlice(smp[consRK])
		}
		var pos int
		if e == nil {
			pos, e = cast.ToInt(mp[posK])
		}
		if e == nil {
			if pos >= len(r.rules) {
				nl := pos - len(r.rules)
				nrl := make([][]rule, nl+1)
				r.rules = append(r.rules, nrl...)
			}
			r.rules[pos] = append(r.rules[pos], rl)
		}
		ok = e != nil
	}
	bLnSrch(inf, len(rm))
	return
}

const (
	unitK     = "unit"
	urlmK     = "urlm"
	impK      = "ipm"
	specK     = "spec"
	startK    = "start"
	activeK   = "active"
	totalK    = "total"
	timesK    = "times"
	infiniteK = "infinite"
	allTimeK  = "allTime"
	spanK     = "span"
	ifaceK    = "iface"
	proxyURLK = "proxyURL"
	consRK    = "consR"
	posK      = "pos"
)

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

func (s *rspec) toSer() (mp interface{}) {
	mp = make([]map[string]interface{}, 0)
	inf := func(i int) {
		inf0 := func(j int) {
			rl := s.rules[i][j]
			// TODO careful with nil references
			rmap = map[string]interface{}{
				unitK: rl.Unit,
				posk:  i,
				urlmK: rl.URLM,
				impK:  rl.IPM,
				spanK: map[string]interface{}{
					startK:    rl.Span.Start.String(),
					activeK:   rl.Span.Active.String(),
					totalK:    rl.Span.Total.String(),
					infiniteK: rl.Span.Infinite,
					allTimeK:  rl.Span.AllTime,
				},
				spec: map[string]interface{}{
					ifaceK:    rl.Spec.Iface,
					proxyURLK: rl.Spec.ProxyURL,
					consRK:    rl.Spec.ConsR,
				},
			}
			mp = append(mp, rmap)
		}
		forall(inf0, len(s.rules[i]))
	}
	forall(inf, len(s.rules))
	return
}

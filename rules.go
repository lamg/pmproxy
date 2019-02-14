package pmproxy

import (
	"context"
	"encoding/json"
	"github.com/lamg/proxy"
	"net"
	"net/url"
	"time"
)

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	ConsR    []string `json:"consR"`
}

func (m *requestMatcher) init() (e error) {
	r.urlm, e = regexp.Compile(r.URLM)
	if e == nil {
		r.Spec.ProxyURL, e = url.Parse(s.ProxyURL)
	}
	return
}

func (s *spec) fromMap(i interface{}) (e error) {
	fe := func(d error) { d = e }
	kf := []kFuncI{
		{
			ifaceK,
			func(i interface{}) {
				s.Iface = stringE(i, fe)
			},
		},
		{
			proxyURLK,
			func(i interface{}) {
				s.ProxyURL = stringE(i, fe)
			},
		},
		{
			proxyURLK,
			func(i interface{}) {
				fe(s.init())
			},
		},
		{
			consRK,
			func(i interface{}) {
				s.ConsR = stringSliceE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (s *spec) toMap() (i interface{}) {
	m = map[string]interface{}{
		ifaceK:    s.Iface,
		proxyURLK: s.ProxyURL,
		consRK:    s.ConsR,
	}
	return
}

type requestMatcher struct {
	Unit bool   `json:"unit"`
	URLM string `json:"urlm"`
	urlm *regexp.Regexp
	Span *rt.RSpan `json:"span"`
	IPM  string    `json:"ipm"`

	Spec *spec `json:"spec"`
}

type rules struct {
	mts [][]requestMatcher
	ipm func(string) (ipMatcher, bool)
}

func (r *rules) match(meth, ürl, rAddr string,
	t time.Time) (s *spec) {
	ip, _, _ := net.SplitHostPort(rAddr)
	ib := func(i, j int) (b bool) {
		a := r.mts[i]
		ipm, ok := r.ipm(a[j].IPM)
		b = (a[j].Unit == (!ok || ipm(ip))) &&
			(a[j].urlm == nil ||
				a[j].urlm.MatchString(url)) &&
			(a[j].Span == nil || a[j].Span.ContainsTime(t))
		return
	}
	inf := func(i int) {
		ns := new(spec)
		b := trueFF(func(j int) (b bool) {
			b = ib(i, j)
			if b {
				sp := r.mts[i][j].Spec
				ns.Iface = sp.Iface
				ns.ProxyURL = sp.ProxyURL
				ns.proxyURL = sp.proxyURL
				ns.ConsR = append(ns.ConsR, sp.ConsR...)
			}
			return
		},
			len(r.mts[i]),
		)
		if b {
			if s.Iface == "" {
				s.Iface = ns.Iface
			}
			if s.ProxyURL == "" {
				s.ProxyURL = ns.ProxyURL
				s.proxyURL = ns.proxyURL
			}
			s.ConsR = append(s.ConsR, ns.ConsR)
		}
	}
	forall(inf, len(r.mts))
	return
}

func (r *rules) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			add,
			func() {
				c.e = c.RequestMatcher.init()
				if c.e == nil {
					c.e = r.add(c.Pos, c.RequestMatcher)
				}
			},
		},
		{
			del,
			func() {
				c.e = r.delete(c.Pos)
			},
		},
		{
			show,
			func() {
				c.bs, c.e = json.Marshal(r.mts)
			},
		},
	}
	return
}

func (r *rules) add(pos []int, rm *requestMatcher) (e error) {
	if len(pos) == 1 {
		if pos[0] == -1 {
			s.mts = append(s.mts, []requestMatcher{*rm})
		} else if pos[0] >= 0 && pos[0] < len(s.mts) {
			s.mts = append(s.mts[:pos[0]],
				append([][]requestMatcher{{*rm}},
					s.mts[pos[0]:]...)...)
		} else {
			e = indexOutOfRange(pos[0], len(s.mts))
		}
	} else if len(pos) == 2 {
		if 0 <= pos[0] && pos[0] < len(s.mts) {
			mt := s.mts[pos[0]]
			if pos[1] == -1 {
				s.mts[pos[0]] = append(mt, *rm)
			} else if 0 <= pos[1] &&
				pos[1] < len(mt) {
				s.mts[pos[0]] = append(mt[:pos[1]],
					append([]requestMatcher{*rm}, mt[pos[1]:]...)...)
			} else {
				e = indexOutOfRange(pos[1], len(mt))
			}
		}
	} else {
		e = invalidArgs(pos)
	}
	return
}

func (r *rules) delete(pos []int) (e error) {
	argc := len(pos)
	if argc < len(s.mts) {
		if argc == 1 {
			s.mts = append(s.mts[:pos[0]],
				s.mts[pos[0]+1:]...)
			// no index out of range
		} else if argc == 2 {
			s.mts[pos[0]] = append(s.mts[pos[0]][:pos[1]],
				s.mts[pos[0]][pos[1]+1:]...)
		} else {
			e = invalidArgs(pos)
		}
	} else {
		e = indexOutOfRange(argc, len(s.mts))
	}
	return
}

package pmproxy

import (
	"encoding/json"
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/cast"
	"net"
	"net/url"
	"regexp"
	"time"
)

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	ConsR    []string `json:"consR"`
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
	i = map[string]interface{}{
		ifaceK:    s.Iface,
		proxyURLK: s.ProxyURL,
		consRK:    s.ConsR,
	}
	return
}

func (s *spec) init() (e error) {
	s.proxyURL, e = url.Parse(s.ProxyURL)
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

func (m *requestMatcher) init() (e error) {
	m.urlm, e = regexp.Compile(m.URLM)
	return
}

func (m *requestMatcher) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			unitK,
			func(i interface{}) {
				m.Unit = boolE(i, fe)
			},
		},
		{
			urlmK,
			func(i interface{}) {
				m.URLM = stringE(i, fe)
			},
		},
		{
			urlmK,
			func(i interface{}) {
				fe(m.init())
			},
		},
		{
			spanK,
			func(i interface{}) {
				m.Span = new(rt.RSpan)
				fe(fromMapSpan(m.Span, i))
			},
		},
		{
			ipmK,
			func(i interface{}) {
				m.IPM = stringE(i, fe)
			},
		},
		{
			string(specK),
			func(i interface{}) {
				m.Spec = new(spec)
				fe(m.Spec.fromMap(i))
			},
		},
		{
			string(specK),
			func(i interface{}) {
				fe(m.Spec.init())
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
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
				a[j].urlm.MatchString(ürl)) &&
			(a[j].Span == nil || a[j].Span.ContainsTime(t))
		return
	}
	inf := func(i int) {
		ns := new(spec)
		b, _ := trueForall(func(j int) (b bool) {
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
			s.ConsR = append(s.ConsR, ns.ConsR...)
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
				rm := new(requestMatcher)
				c.e = rm.fromMap(c.Object)
				if c.e == nil {
					c.e = r.add(c.Pos, rm)
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
			get,
			func() {
				c.bs, c.e = json.Marshal(r.mts)
			},
		},
	}
	return
}

func (r *rules) toMap() (i interface{}) {
	var smp []map[string]interface{}
	inf := func(i, j int) {
		rm := r.mts[i][j]
		// TODO careful with nil references
		rmap := map[string]interface{}{
			unitK:         rm.Unit,
			posK:          i,
			urlmK:         rm.URLM,
			ipmK:          rm.IPM,
			spanK:         toMapSpan(rm.Span),
			string(specK): rm.Spec.toMap(),
		}
		smp = append(smp, rmap)
	}
	forall(
		func(i int) {
			forall(func(j int) { inf(i, j) }, len(r.mts[i]))
		},
		len(r.mts),
	)
	return
}

func (r *rules) fromMap(i interface{}) (e error) {
	var ms []interface{}
	var prs []*posReq
	fs := []func(){
		func() {
			ms, e = cast.ToSliceE(i)
		},
		func() {
			ib := func(i int) (ok bool) {
				pr := new(posReq)
				e = pr.fromMap(i)
				ok = e == nil
				if ok {
					prs = append(prs, pr)
				}
				return
			}
			trueForall(ib, len(ms))
		},
		func() {
			inf := func(i int) {
				pos := prs[i].pos
				if pos >= len(r.mts) {
					diff := pos - len(r.mts)
					ext := make([][]requestMatcher, diff+1)
					r.mts = append(r.mts, ext...)
				}
				r.mts[pos] = append(r.mts[pos], *prs[i].req)
			}
			forall(inf, len(prs))
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

type posReq struct {
	pos int
	req *requestMatcher
}

func (r *posReq) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			posK,
			func(i interface{}) {
				r.pos = intE(i, fe)
			},
		},
		{
			reqK,
			func(i interface{}) {
				r.req = new(requestMatcher)
				fe(r.req.fromMap(i))
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (r *rules) add(pos []int,
	rm *requestMatcher) (e error) {
	if len(pos) == 1 {
		if pos[0] == -1 {
			r.mts = append(r.mts, []requestMatcher{*rm})
		} else if pos[0] >= 0 && pos[0] < len(r.mts) {
			r.mts = append(r.mts[:pos[0]],
				append([][]requestMatcher{{*rm}},
					r.mts[pos[0]:]...)...)
		} else {
			e = indexOutOfRange(pos[0], len(r.mts))
		}
	} else if len(pos) == 2 {
		if 0 <= pos[0] && pos[0] < len(r.mts) {
			mt := r.mts[pos[0]]
			if pos[1] == -1 {
				r.mts[pos[0]] = append(mt, *rm)
			} else if 0 <= pos[1] &&
				pos[1] < len(mt) {
				r.mts[pos[0]] = append(mt[:pos[1]],
					append([]requestMatcher{*rm}, mt[pos[1]:]...)...)
			} else {
				e = indexOutOfRange(pos[1], len(mt))
			}
		}
	} else {
		e = invalidPos(pos)
	}
	return
}

func (r *rules) delete(pos []int) (e error) {
	argc := len(pos)
	if argc < len(r.mts) {
		if argc == 1 {
			r.mts = append(r.mts[:pos[0]],
				r.mts[pos[0]+1:]...)
			// no index out of range
		} else if argc == 2 {
			r.mts[pos[0]] = append(r.mts[pos[0]][:pos[1]],
				r.mts[pos[0]][pos[1]+1:]...)
		} else {
			e = invalidPos(pos)
		}
	} else {
		e = indexOutOfRange(argc, len(r.mts))
	}
	return
}

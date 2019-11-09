package managers

import (
	"encoding/json"
	alg "github.com/lamg/algorithms"
	pred "github.com/lamg/predicate"
	"net/url"
	"strings"
)

type rules struct {
	predicate *pred.Predicate
}

const ()

func newRules(preds string) (r *rules, e error) {
	r = new(rules)
	r.predicate, e = pred.Parse(strings.NewReader(preds))
	return
}

func (m *rules) exec(c *Cmd) {
	if c.Cmd == Match || c.Cmd == Discover {
		ninterp := make(map[string]*MatchType, len(c.interp))
		var proxyURL *url.URL
		var netIface string
		interp := func(name string) (r, def bool) {
			if name == pred.TrueStr || name == pred.FalseStr {
				r, def = name == pred.TrueStr, true
			} else {
				var mt *MatchType
				mt, def = c.interp[name]
				if def {
					ninterp[name] = mt
					r = mt.Match
					if r {
						kf := []alg.KFunc{
							{
								DwnConsRK,
								func() { c.consR = append(c.consR, name) },
							},
							{IfaceK, func() { netIface = c.iface }},
							{ParentProxyK, func() { proxyURL = c.parentProxy }},
						}
						alg.ExecF(kf, mt.Type)
					}
				}
			}
			return
		}
		p := pred.Reduce(m.predicate, interp)
		c.interp = ninterp // hiding managers not reached by evaluation
		c.parentProxy, c.iface = proxyURL, netIface
		c.ok = p.String == pred.TrueStr
		c.result = pred.String(p)
		if c.Cmd == Discover {
			dr := &DiscoverRes{
				MatchMng: c.interp,
				Result:   c.result,
			}
			c.data, c.err = json.Marshal(dr)
		}
	}
}

func (m *rules) paths(sm, dw, ipm, ps, ns []string) (ms []mngPath) {
	// depends on the matchers required to evaluate the predicate
	// for the specific instance of Cmd, which is defined at after
	// initialization. The solution is make the command go through
	// all matchers, and its dependencies,before sending it to rules
	mts, sps := make([]string, 0), []*pred.Predicate{m.predicate}
	for len(sps) != 0 {
		last := len(sps) - 1
		p := sps[last]
		sps = sps[:last]
		if p.String != "" {
			mts = append(mts, p.String)
		} else {
			if p.A != nil {
				sps = append(sps, p.A)
			}
			if p.B != nil {
				sps = append(sps, p.B)
			}
		}
	}
	matchers := make(map[string][]mngPath)
	mngPF := []func(string) []mngPath{
		func(s string) []mngPath {
			return []mngPath{
				{name: adminsMng, cmd: Protect},
				{name: ipUserMng, cmd: Get},
				{name: s, cmd: Match},
			}
		},
		simpleMatchPath,
		simpleMatchPath,
		simpleMatchPath,
		simpleMatchPath,
	}
	names := [][]string{sm, dw, ipm, ps, ns}
	alg.Forall(
		func(i int) { matchersToMap(names[i], mngPF[i], matchers) },
		len(names),
	)
	paths := make([]mngPath, 0)
	for _, j := range mts {
		pth, ok := matchers[j]
		if ok {
			paths = append(paths, pth...)
		}
	}
	matchDeps := append(paths, mngPath{name: RulesK, cmd: Match})
	discoverDeps := append(paths,
		mngPath{name: RulesK, cmd: Discover})
	ms = []mngPath{
		{
			name: RulesK,
			cmd:  Match,
			mngs: matchDeps,
		},
		{
			name: RulesK,
			cmd:  Discover,
			mngs: discoverDeps,
		},
	}
	return
}

func simpleMatchPath(s string) []mngPath {
	return []mngPath{
		{name: s, cmd: Match},
	}
}

func matchersToMap(xs []string, ps func(string) []mngPath,
	ms map[string][]mngPath) {
	alg.Forall(func(i int) { ms[xs[i]] = ps(xs[i]) }, len(xs))
}

package managers

import (
	"encoding/json"
	"fmt"
	pred "github.com/lamg/predicate"
	"strings"
)

type rules struct {
	predicate *pred.Predicate
}

const (
	RulesK = "rules"
)

func newRules(preds string) (r *rules, e error) {
	r = new(rules)
	r.predicate, e = pred.Parse(strings.NewReader(preds))
	return
}

func (m *rules) exec(c *Cmd) (term bool) {
	if c.Cmd == Match || c.Cmd == Discover {
		interp := func(name string) (r, def bool) {
			if name == pred.TrueStr || name == pred.FalseStr {
				r, def = name == pred.TrueStr, true
			} else {
				var mt *MatchType
				mt, def = c.interp[name]
				if def {
					r = mt.Match
				}
			}
			return
		}
		p := pred.Reduce(m.predicate, interp)
		c.Ok = p.String == pred.TrueStr
		c.String = pred.String(p)
		if c.Cmd == Discover {
			dr := &DiscoverRes{
				MatchMng: c.interp,
				Result:   c.String,
			}
			c.Data, c.Err = json.Marshal(dr)
		}
	}
	return
}

func (m *rules) paths(sm, dw, ipm string) (ms []mngPath) {
	// depends on the matchers required to evaluate the predicate
	// for the specific instance of Cmd, which is defined at after
	// initialization. The solution is make the command go through
	// all matchers, and it dependencies,before sending it to rules
	mts, sps := make([]string, 0), []*pred.Predicate{m.predicate}
	fmt.Println(m.predicate, m.predicate.A, m.predicate.B)
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
	matchers := map[string][]mngPath{
		sm: []mngPath{
			{name: ipUserMng, cmd: Get},
			{name: sm, cmd: Match},
		},
		dw:  []mngPath{{name: dw, cmd: Match}},
		ipm: []mngPath{{name: ipm, cmd: Match}},
	}
	paths := make([]mngPath, 0, len(mts))
	fmt.Println(mts)
	for _, j := range mts {
		pth, ok := matchers[j]
		if ok {
			paths = append(paths, pth...)
		}
	}
	ms = []mngPath{
		{
			name: RulesK,
			cmd:  Match,
			mngs: append(paths, mngPath{name: RulesK, cmd: Match}),
		},
		{
			name: RulesK,
			cmd:  Discover,
			mngs: append(paths, mngPath{name: RulesK, cmd: Discover}),
		},
	}
	return
}

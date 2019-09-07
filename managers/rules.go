package managers

import (
	"encoding/json"
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
	if c.Cmd == Match {
		term = true
		interp := func(name string) (r, def bool) {
			var mt *MatchType
			mt, def = c.interp[name]
			if !def {
				c.Manager, term = name, false
			} else {
				r = mt.Match
			}
			return
		}
		p := pred.Reduce(m.predicate, interp)
		if term {
			c.Ok = p.String == pred.TrueStr
			c.String = pred.String(p)
			dr := &DiscoverRes{
				MatchMng: c.interp,
				Result:   c.String,
			}
			c.Data, c.Err = json.Marshal(dr)
		}
	}
	return
}

package managers

/*
# Matchers

This manager receives a `match` command and reduces the `matchers.rules` predicate with the available interpretation at `matchers.interp`. If the value of a predicate is not defined in the interpretation, then the command (`c`) is left in a state ready for evaluating by the manager with the same name of the predicate. That manager appends the `matchResponse` key to `c.defKeys`, sets the `c.String` with its own name so isn't lost when returns to the `matchers` manager, and the `c.Ok` field as the result of evaluating the predicate it represents. After that `matchers.rules` is evaluated again until there are no more undefined predicates.
*/

import (
	pred "github.com/lamg/predicate"
)

type matchers struct {
	rules *pred.Predicate
}

func (m *matchers) exec(c *Cmd) (term bool) {
	if c.Cmd == match {
		term = true
		interp := func(name string) (r, def bool) {
			r, def = c.interp[name]
			if !def {
				c.Manager, term = name, false
			}
			return
		}
		p := pred.Reduce(m.rules, interp)
		if term {
			c.Ok = p.String == pred.TrueStr
			c.String = pred.String(p)
		}
	}
	return
}

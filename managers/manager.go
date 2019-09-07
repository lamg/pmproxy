// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package managers

import (
	"fmt"
	"sync"
)

type manager struct {
	mngs *sync.Map
}

func newManager() (m *manager) {
	m = &manager{mngs: new(sync.Map)}
	return
}

type mngCmd struct {
	mng string
	cmd string
}

func (m *manager) exec(c *Cmd) (proc bool) {
	c.interp = make(map[string]*MatchType)
	var mngs []*mngCmd
	proc = true
	for (proc || len(mngs) != 0) && c.Err == nil {
		if proc {
			term, prev := m.execStep(c)
			if !term {
				mngs = append(mngs, prev)
			}
			proc = !term
		} else if len(mngs) != 0 {
			last := len(mngs) - 1
			next := mngs[last]
			mngs = mngs[:last]
			c.Manager = next.mng
			c.Cmd = next.cmd
			proc = true
		}
	}
	return
}

func (m *manager) execStep(c *Cmd) (term bool, prev *mngCmd) {
	prev = &mngCmd{mng: c.Manager, cmd: c.Cmd}
	v, ok := m.mngs.Load(c.Manager)
	if ok {
		term = v.(func(*Cmd) bool)(c)
	} else {
		c.Err = fmt.Errorf("Not found manager '%s'", c.Manager)
	}
	return
}

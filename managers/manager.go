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
	alg "github.com/lamg/algorithms"
	"sync"
)

type manager struct {
	mngs  *sync.Map
	paths []mngPath
}

type mngPath struct {
	name string
	cmd  string
	mngs []mngPath
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
	ib := func(i int) (ok bool) {
		pth := m.paths[i]
		ok = pth.name == c.Manager && pth.cmd == c.Cmd
		return
	}
	ok, n := alg.BLnSrch(ib, len(m.paths))
	if ok {
		fnd := m.paths[n]
		ib0 := func(i int) (ok bool) {
			curr := fnd.mngs[i]
			c.Manager, c.Cmd = curr.name, curr.cmd
			m.execStep(c)
			ok = c.Err != nil
			return
		}
		alg.BLnSrch(ib0, len(fnd.mngs))
	} else {
		c.Err = fmt.Errorf("Not found manager '%s'"+
			" with command '%s'", c.Manager, c.Cmd)
	}
	return
}

func (m *manager) execStep(c *Cmd) {
	v, ok := m.mngs.Load(c.Manager)
	if ok {
		v.(func(*Cmd) bool)(c)
	} else {
		c.Err = fmt.Errorf("Not found manager '%s'", c.Manager)
	}
	return
}

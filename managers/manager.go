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
	alg "github.com/lamg/algorithms"
	"sync"
)

type manager struct {
	mngs  *sync.Map
	paths []mngPath
	// execution by a specific manager is only possible if it
	// appears both in paths and mngs
}

type mngPath struct {
	name string
	cmd  string
	mngs []mngPath
}

func newManager() (m *manager) {
	m = &manager{mngs: new(sync.Map)}
	m.paths = append(m.paths, mngPath{name: Skip})
	return
}

type mngCmd struct {
	mng string
	cmd string
}

func (m *manager) exec(c *Cmd, ip string) (data []byte, e error) {
	c.interp, c.ip = make(map[string]*MatchType), ip
	if c.Info == nil {
		c.Info = new(UserInfo)
	}
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
			ok = c.err != nil
			return
		}
		alg.BLnSrch(ib0, len(fnd.mngs))
		data, e = c.data, c.err
	} else {
		e = &ManagerErr{Mng: c.Manager, Cmd: c.Cmd}
	}
	return
}

func (m *manager) execStep(c *Cmd) {
	v, ok := m.mngs.Load(c.Manager)
	if ok {
		v.(func(*Cmd))(c)
	} else {
		c.err = &ManagerErr{Mng: c.Manager, Cmd: c.Cmd}
	}
	return
}

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

package pmproxy

import (
	"encoding/json"
)

type groupIPM struct {
	ipg      ipGroup
	ipGroupN string
	name     string
	group    string
}

func (m *groupIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				m.name = stringE(i, fe)
			},
		},
		{
			ipGroupNK,
			func(i interface{}) {
				m.ipGroupN = stringE(i, fe)
			},
		},
		{
			groupK,
			func(i interface{}) {
				m.group = stringE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (m *groupIPM) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			set,
			func() {
				m.group = c.String
			},
		},
		{
			get,
			func() {
				c.bs, c.e = json.Marshal(m.toMap())
			},
		},
	}
	return
}

func (m *groupIPM) toMap() (i interface{}) {
	i = map[string]interface{}{
		groupK:    m.group,
		nameK:     m.name,
		ipGroupNK: m.ipGroupN,
	}
	return
}

func (m *groupIPM) match(ip string) (ok bool) {
	gs, _ := m.ipg(ip)
	ib := func(i int) (b bool) {
		b = m.group == gs[i]
		return
	}
	ok, _ = bLnSrch(ib, len(gs))
	return
}

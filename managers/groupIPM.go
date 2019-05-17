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
	"encoding/json"
)

type groupIPM struct {
	userGroup  func(string) ([]string, error)
	userGroupN string
	ipUser     func(string) (string, bool)
	name       string
	group      string
}

func (m *groupIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			NameK,
			func(i interface{}) {
				m.name = stringE(i, fe)
			},
		},
		{
			userGroupNK,
			func(i interface{}) {
				m.userGroupN = stringE(i, fe)
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

func (m *groupIPM) managerKF(c *Cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			Set,
			func() {
				m.group = c.String
			},
		},
		{
			Get,
			func() {
				c.bs, c.e = json.Marshal(m.toMap())
			},
		},
	}
	return
}

func (m *groupIPM) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		groupK:      m.group,
		NameK:       m.name,
		userGroupNK: m.userGroupN,
	}
	return
}

func (m *groupIPM) match(ip string) (ok bool) {
	user, _ := m.ipUser(ip)
	gs, _ := m.userGroup(user)
	ib := func(i int) (b bool) {
		b = m.group == gs[i]
		return
	}
	ok, _ = bLnSrch(ib, len(gs))
	return
}

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
	alg "github.com/lamg/algorithms"
)

type groupIPM struct {
	UserDBN string `toml:"userDBN"`
	Name    string `toml:"name"`
	Group   string `toml:"group"`
}

const (
	GroupIPMK = "groupIPM"
)

func (m *groupIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Set,
			func() {
				m.Group = c.String
			},
		},
		{
			Get,
			func() {
				c.Data, c.Err = json.Marshal(m)
			},
		},
		{
			Match,
			func() {
				if len(c.Groups) == 0 && c.Err == nil {
					c.Manager = m.UserDBN
					term = false
				} else if len(c.Groups) != 0 {
					c.Ok, _ = alg.BLnSrch(
						func(i int) bool { return m.Group == c.Groups[i] },
						len(c.Groups))
					c.interp[m.Name] = &MatchType{
						Type:  GroupIPMK,
						Match: c.Ok,
					}
					term = true
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

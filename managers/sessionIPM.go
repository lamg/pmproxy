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
)

type sessionIPM struct {
	Name string `toml:"name"`
	Auth string `toml:"auth"`
}

const (
	Open        = "open"
	Close       = "close"
	Auth        = "authenticate"
	Check       = "check"
	SessionIPMK = "sessionIPM"
)

func (m *sessionIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Check,
			func() {
				c.Ok = c.User == c.String
				if !c.Ok {
					fmt.Errorf("Check failed: '%s' ≠ '%s'", c.User, c.String)
				}
			},
		},
		{
			Match,
			func() {
				c.Ok = c.User != ""
				c.interp[m.Name] = &MatchType{
					Type:  SessionIPMK,
					Match: c.Ok,
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func (m *sessionIPM) paths() (ms []mngPath) {
	ms = []mngPath{
		{
			name: m.Name,
			cmd:  Open,
			mngs: []mngPath{
				{name: m.Auth, cmd: Auth},
				{name: cryptMng, cmd: encrypt},
				{name: ipUserMng, cmd: Open},
			},
		},
		{
			name: m.Name,
			cmd:  Close,
			mngs: []mngPath{
				{name: cryptMng, cmd: decrypt},
				{name: ipUserMng, cmd: Close},
			},
		},
		{
			name: m.Name,
			cmd:  Renew,
			mngs: []mngPath{
				{name: cryptMng, cmd: Renew},
			},
		},
		{
			name: m.Name,
			cmd:  Check,
			mngs: []mngPath{
				{name: ipUserMng, cmd: Get},
				{name: cryptMng, cmd: decrypt},
				{name: m.Name, cmd: Check},
			},
		},
	}
	return
}

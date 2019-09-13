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

const (
	groupsK = "group"
)

type mapDB struct {
	Name      string              `toml:"name"`
	UserPass  map[string]string   `toml:"userPass"`
	UserGroup map[string][]string `toml:"userGroups"`
}

func (d *mapDB) auth(user, pass string) (nuser string, e error) {
	if len(d.UserPass) == 0 {
		e = fmt.Errorf("Empty user-password map")
	} else {
		nuser = user
		p, ok := d.UserPass[user]
		if !ok {
			e = fmt.Errorf("No user '%s'", user)
		} else if p != pass {
			e = fmt.Errorf("Incorrect password")
		}
	}
	return
}

func (d *mapDB) userGroups(user string) (gs []string, e error) {
	if len(d.UserGroup) == 0 {
		e = fmt.Errorf("Empty user-groups map")
	} else {
		var ok bool
		gs, ok = d.UserGroup[user]
		if !ok {
			e = fmt.Errorf("No user '%s'", user)
		}
	}
	return
}

func (d *mapDB) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Auth,
			func() {
				c.User, c.Err = d.auth(c.Cred.User, c.Cred.Pass)
			},
		},
		{
			Get,
			func() {
				if c.Ok {
					// checks if previous manager signaled this step
					// to be executed, since some of them determines that
					// property at runtime, after initialization
					c.Groups, c.Err = d.userGroups(c.User)
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

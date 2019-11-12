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
)

type mapDB struct {
	Name      string              `toml:"name"`
	UserPass  map[string]string   `toml:"userPass"`
	UserGroup map[string][]string `toml:"userGroups"`
}

func (d *mapDB) auth(user, pass string) (nuser string, e error) {
	if len(d.UserPass) == 0 {
		e = &StringErr{"Empty user-password map"}
	} else {
		nuser = user
		p, ok := d.UserPass[user]
		if !ok {
			e = &NoUser{User: user, DB: d.Name}
		} else if p != pass {
			e = &StringErr{"Incorrect password"}
		}
	}
	return
}

func (d *mapDB) userGroups(info *UserInfo) (e error) {
	if len(d.UserGroup) == 0 {
		e = &StringErr{"Empty user-password map"}
	} else {
		var ok bool
		info.Groups, ok = d.UserGroup[info.UserName]
		info.Name = info.UserName
		if !ok {
			e = &NoUser{User: info.UserName}
		}
	}
	return
}

func (d *mapDB) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			Auth,
			func() {
				c.loggedBy = &userAuth{auth: d.Name}
				c.loggedBy.user, c.err = d.auth(c.Cred.User, c.Cred.Pass)
			},
		},
		{
			Get,
			func() {
				if c.loggedBy.auth == d.Name {
					c.Info.UserName = c.loggedBy.user
					c.err = d.userGroups(c.Info)
				}
			},
		},
		{
			GetOther,
			func() {
				c.err = d.userGroups(c.Info)
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
}

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
	userK     = "user"
	groupK    = "group"
	nameK     = "name"
	authCmd   = "auth"
	groupsCmd = "groups"
	nameCmd   = "name"
)

type mapDB struct {
	name      string
	userPass  map[string]string
	userGroup map[string][]string
}

func (d *mapDB) auth(user, pass string) (nuser string, e error) {
	nuser = user
	p, ok := d.userPass[user]
	if !ok {
		e = fmt.Errorf("No user '%s'", user)
	} else if p != pass {
		e = fmt.Errorf("Incorrect password")
	}
	return
}

func (d *mapDB) userGroups(user string) (gs []string, e error) {
	gs, ok := d.userGroup[user]
	if !ok {
		e = fmt.Errorf("No user '%s'", user)
	}
	return
}

func (d *mapDB) exec(c *Cmd) (term bool) {
	// TODO
	kf := []alg.KFunc{
		{
			authCmd,
			func() {
				c.User, c.Err = d.auth(c.Cred.User,
					c.Cred.Pass)
				setKey(c, userK)
				term = true
			},
		},
		{
			groupsCmd,
			func() {
				term = hasKey(c, userK)
				if term {
					c.Groups, c.Err = d.userGroups(c.User)
				} else {
					c.Cmd, c.Manager = ipUserCmd, ipUserMng
				}
			},
		},
		{
			nameCmd,
			func() {
				if hasKey(c, userK) {

				} else {

				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func setKey(c *Cmd, key string) {
	c.Object[key] = true
}

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
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/cast"
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

func (d *mapDB) fromMap(i interface{}) (e error) {
	var mp map[string]interface{}
	fs := []func(){
		func() { mp, e = cast.ToStringMapE(i) },
		func() {
			upm, e = cast.ToStringMapStringE(mp[userPassK])
		},
		func() {
			gm, e = cast.ToStringMapStringSliceE(mp[userGroupsK])
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
}

func (d *mapDB) auth(user, pass string) (nuser string, e error) {
	nuser = user
	p, ok := upm[user]
	if !ok {
		e = fmt.Errorf("No user '%s'", user)
	} else if p != pass {
		e = fmt.Errorf("Incorrect password")
	}
	return
}

func (d *mapDB) userGroups(user string) (gs []string, e error) {
	gs, ok := gm[user]
	if !ok {
		e = fmt.Errorf("No user '%s'", user)
	}
	return
}

func (d *userDB) exec(c *Cmd) (term bool) {
	// TODO
	kf = []alg.KFunc{
		{
			authCmd,
			func() {
				c.User, c.e = d.auth(c.Credentials.User,
					c.Credentials.Pass)
				setKey(c, userK)
				term = true
			},
		},
		{
			groupsCmd,
			func() {
				term = hasKey(c, userK)
				if term {
					c.Groups, c.e = d.userGroups(c.User)
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

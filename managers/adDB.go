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
	ld "github.com/lamg/ldaputil"
)

type adDB struct {
	Name string
	Addr string
	Suff string
	Bdn  string
	User string
	Pass string
	ldap *ld.Ldap
}

func (a *adDB) init() (e error) {
	a.ldap = ld.NewLdapWithAcc(a.Addr, a.Suff, a.Bdn, a.User, a.Pass)
	return
}

func (d *adDB) auth(user, pass string) (nuser string, e error) {
	nuser, e = d.ldap.AuthAndNorm(user, pass)
	return
}

func (d *adDB) userGroups(user string) (gs []string, e error) {
	mp, e := d.ldap.FullRecordAcc(user)
	if e == nil {
		gs, e = d.ldap.MembershipCNs(mp)
	}
	return
}

func (d *adDB) userName(user string) (name string, e error) {
	mp, e := d.ldap.FullRecordAcc(user)
	if e == nil {
		name, e = d.ldap.FullName(mp)
	}
	return
}

func (d *adDB) exec(c *Cmd) (term bool) {
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
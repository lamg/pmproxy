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
	Name string `toml:"name"`
	Addr string `toml:"addr"`
	Suff string `toml:"suff"`
	Bdn  string `toml:"bdn"`
	User string `toml:"user"`
	Pass string `toml:"pass"`
	ldap *ld.Ldap
}

func (d *adDB) init() (e error) {
	d.ldap = ld.NewLdapWithAcc(d.Addr, d.Suff, d.Bdn, d.User, d.Pass)
	return
}

func (d *adDB) auth(user, pass string) (nuser string, e error) {
	nuser, e = d.ldap.AuthAndNorm(user, pass)
	return
}

func (d *adDB) userInfo(info *UserInfo) (e error) {
	mp, e := d.ldap.FullRecordAcc(info.UserName)
	if e == nil {
		info.Groups, e = d.ldap.MembershipCNs(mp)
	}
	if e == nil {
		info.Name, e = d.ldap.FullName(mp)
	}
	return
}

func (d *adDB) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			Auth,
			func() {
				c.loggedBy = new(userSessionIPM)
				c.loggedBy.user, c.err = d.auth(c.Cred.User, c.Cred.Pass)
			},
		},
		{
			Get,
			func() {
				c.Info.UserName = c.loggedBy.user
				c.err = d.userInfo(c.Info)
			},
		},
		{
			GetOther,
			func() {
				c.err = d.userInfo(c.Info)
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
}

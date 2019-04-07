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
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/cast"
)

type userDB struct {
	name       string
	adOrMap    bool
	params     map[string]interface{}
	auth       func(string, string) (string, error)
	userGroups func(string) ([]string, error)
	userName   func(string) (string, error)
}

func (d *userDB) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.name = stringE(i, fe)
			},
		},
		{
			adOrMapK,
			func(i interface{}) {
				d.adOrMap = boolE(i, fe)
			},
		},
		{
			paramsK,
			func(i interface{}) {
				d.params = stringMapE(i, fe)
				if e == nil {
					if d.adOrMap {
						fe(d.fromMapAD(i))
					} else {
						fe(d.fromMapMap(i))
					}
				}
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

type keyVal struct {
	k, v string
}

func (d *userDB) fromMapAD(i interface{}) (e error) {
	addr, suff, bdn, user, pass :=
		keyVal{k: addrK}, keyVal{k: suffK}, keyVal{k: bdnK},
		keyVal{k: userK}, keyVal{k: passK}
	ks := []keyVal{addr, suff, bdn, user, pass}
	mp, e := cast.ToStringMapE(i)
	ok, _ := trueForall(
		func(i int) (b bool) {
			ks[i].v, e = cast.ToStringE(mp[ks[i].k])
			b = e == nil
			return
		},
		len(ks),
	)
	if ok {
		ldap := ld.NewLdapWithAcc(addr.v, suff.v, bdn.v,
			user.v, pass.v)
		d.auth = ldap.AuthAndNorm
		d.userGroups = func(user string) (gs []string, e error) {
			mp, e := ldap.FullRecordAcc(user)
			if e == nil {
				gs, e = ldap.MembershipCNs(mp)
			}
			return
		}
		d.userName = func(user string) (name string, e error) {
			mp, e := ldap.FullRecordAcc(user)
			if e == nil {
				name, e = ldap.FullName(mp)
			}
			return
		}
	}
	return
}

func (d *userDB) fromMapMap(i interface{}) (e error) {
	var mp map[string]interface{}
	var upm map[string]string
	var gm map[string][]string
	fs := []func(){
		func() { mp, e = cast.ToStringMapE(i) },
		func() {
			upm, e = cast.ToStringMapStringE(mp[userPassK])
		},
		func() {
			gm, e = cast.ToStringMapStringSliceE(mp[userGroupsK])
		},
	}
	ok := trueFF(fs, func() bool { return e == nil })
	if ok {
		d.auth = func(user, pass string) (nuser string,
			e error) {
			nuser = user
			p, ok := upm[user]
			if !ok {
				e = noKey(user)
			} else if p != pass {
				e = incorrectPassword()
			}
			return
		}
		d.userGroups = func(user string) (gs []string, e error) {
			gs, ok := gm[user]
			if !ok {
				e = noKey(user)
			}
			return
		}
		d.userName = func(user string) (name string, e error) {
			name = user
			return
		}
	}
	return
}

func (d *userDB) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		nameK:    d.name,
		adOrMapK: d.adOrMap,
		paramsK:  d.params,
	}
	return
}

func (d *userDB) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			showAll,
			func() {
				c.bs, c.e = json.Marshal(d.toMap())
			},
		},
	}
	return
}

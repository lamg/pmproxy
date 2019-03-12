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
	"github.com/c2h5oh/datasize"
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/cast"
	"sync"
)

type userDB struct {
	name       string
	adOrMap    bool
	params     map[string]interface{}
	auth       func(string, string) (string, error)
	userGroups func(string) ([]string, error)
	userName   func(string) (string, error)

	quotaCache  *sync.Map
	groupQuotaM *sync.Map
}

func (d *userDB) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	var m map[string]string
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
		{
			quotaMapK,
			func(i interface{}) {
				m = stringMapStringE(i, fe)
			},
		},
		{
			quotaMapK,
			func(i interface{}) {
				d.groupQuotaM = new(sync.Map)
				d.quotaCache = new(sync.Map)
				for k, v := range m {
					bts := new(datasize.ByteSize)
					e = bts.UnmarshalText([]byte(v))
					if e != nil {
						break
					}
					d.groupQuotaM.Store(k, bts.Bytes())
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

func (d *userDB) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:    d.name,
		adOrMapK: d.adOrMap,
		paramsK:  d.params,
		quotaMapK: func() (m map[string]string) {
			d.groupQuotaM.Range(func(k, v interface{}) (ok bool) {
				sz := datasize.ByteSize(v.(uint64))
				m[k.(string)], ok = sz.HumanReadable(), true
				return
			})
			return
		}(),
	}
	return
}

type userInfo struct {
	Quota    string   `json:"quota"`
	Groups   []string `json:"groups"`
	Name     string   `json:"name"`
	UserName string   `json:"userName"`
}

func (d *userDB) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			showAll,
			func() {
				c.bs, c.e = json.Marshal(d.toMap())
			},
		},
		{
			get,
			func() {
				var data *userInfo
				if c.IsAdmin && c.String != "" {
					data, c.e = d.info(c.String)
				} else {
					data, c.e = d.info(c.User)
				}
				if c.e == nil {
					c.bs, c.e = json.Marshal(data)
				}
			},
		},
	}
	return
}

func (d *userDB) info(user string) (ui *userInfo, e error) {
	n := d.quota(user)
	q := datasize.ByteSize(n).HumanReadable()
	ui = &userInfo{
		Quota:    q,
		UserName: user,
	}
	ui.Groups, e = d.userGroups(user)
	if e == nil {
		ui.Name, e = d.userName(user)
	}
	return
}

func (d *userDB) quota(user string) (n uint64) {
	v, ok := d.quotaCache.Load(user)
	if ok {
		n = v.(uint64)
	} else {
		gs, _ := d.userGroups(user)
		inf := func(i int) {
			q := d.groupQuota(gs[i])
			n = n + q
		}
		forall(inf, len(gs))
		d.quotaCache.Store(user, n)
	}
	return
}

func (d *userDB) groupQuota(g string) (q uint64) {
	v, ok := d.groupQuotaM.Load(g)
	if ok {
		q = v.(uint64)
	}
	return
}

func (d *userDB) delCache(user string) {
	d.quotaCache.Delete(user)
}

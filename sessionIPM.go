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
)

type sessionIPM struct {
	name     string
	iu       *ipUserS
	authName string
	nameAuth func(string) (func(string, string) (string, error),
		bool)
	cr *crypt
}

func (m *sessionIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			NameK,
			func(i interface{}) {
				m.name = stringE(i, fe)
			},
		},
		{
			authNameK,
			func(i interface{}) {
				m.authName = stringE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (m *sessionIPM) managerKF(c *Cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			Open,
			func() {
				c.bs, c.e = m.open(c.Cred, c.RemoteAddr)
			},
		},
		{
			Clöse,
			func() {
				c.bs, c.e = m.close(c.Secret, c.RemoteAddr)
			},
		},
		{
			Get,
			func() {
				if c.IsAdmin {
					c.bs, c.e = m.get(c.Secret, c.RemoteAddr)
				}
			},
		},
		{
			Renew,
			func() {
				c.bs, c.e = m.renew(c.Secret, c.RemoteAddr)
			},
		},
		{
			check,
			func() {
				_, c.e = m.check(c.Secret, c.RemoteAddr)
			},
		},
	}
	return
}

func (m *sessionIPM) match(ip string) (ok bool) {
	_, ok = m.iu.get(ip)
	return
}

func (m *sessionIPM) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		NameK:     m.name,
		authNameK: m.authName,
	}
	return
}

func (m *sessionIPM) open(c *Credentials,
	ip string) (bs []byte, e error) {
	var a func(string, string) (string, error)
	var user string
	fs := []func(){
		func() {
			var ok bool
			a, ok = m.nameAuth(m.authName)
			if !ok {
				e = NoKey(m.authName)
			}
		},
		func() {
			user, e = a(c.User, c.Pass)
		},
		func() {
			var s string
			s, e = m.cr.encrypt(user, m.authName)
			bs = []byte(s)
		},
		func() {
			var oldIP string
			m.iu.mäp.Range(func(k, v interface{}) (cont bool) {
				cont = v.(string) != user
				return
			})
			if oldIP != "" {
				m.iu.mäp.Delete(oldIP)
			}
			m.iu.mäp.Store(ip, user)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (m *sessionIPM) close(secret, ip string) (bs []byte,
	e error) {
	claim, e := m.cr.decrypt(secret)
	if e == nil {
		lusr, ok := m.iu.get(ip)
		if ok && lusr == claim.User {
			m.iu.del(ip)
		}
	}
	return
}

func (m *sessionIPM) get(secret, ip string) (bs []byte,
	e error) {
	_, e = m.check(secret, ip)
	if e == nil {
		mp := map[string]string{}
		m.iu.mäp.Range(func(k, v interface{}) (cont bool) {
			mp[k.(string)] = v.(string)
			cont = true
			return
		})
		bs, e = json.Marshal(mp)
	}
	return
}

func (m *sessionIPM) renew(secret, ip string) (bs []byte, e error) {
	user, e := m.check(secret, ip)
	if e != nil {
		var s string
		s, e = m.cr.encrypt(user, m.authName)
		bs = []byte(s)
	}
	return
}

func (m *sessionIPM) check(secret, ip string) (user string, e error) {
	tkUser, e := m.cr.decrypt(secret)
	user, ok := m.iu.get(ip)
	if e == nil {
		if !(ok && tkUser.User == user) {
			e = userNotLoggedAt(tkUser.User, ip)
		}
	}
	return
}

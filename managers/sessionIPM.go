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
	alg "github.com/lamg/algorithms"
)

type sessionIPM struct {
	name     string
	authName string
}

const (
	Open         = "open"
	Close        = "close"
	authenticate = "authenticate"
)

func (m *sessionIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Open,
			func() {
				if c.User == "" {
					c.Manager = m.authName
					c.Cmd = authenticate
				} else if c.Err == nil && c.Secret == "" {
					c.Manager = cryptMng
					c.Cmd = encrypt
				} else {
					c.Manager = ipUserMng
					c.Cmd = Open
					term = true
				}
			},
		},
		{
			Close,
			func() {
				_, secretOk := c.Object[secretOkK]
				if secretOk && c.e == nil {
					c.Manager = crypt
					c.Cmd = decrypt
				} else if secretOk {
					c.Manager = ipUser
					c.Cmd = delete
				}
			},
		},
		{
			Get,
			func() {
				_, admDef := c.Object[isAdminK]
				if admDef {
					_, sessionsDef := c.Object[sessionsK]
					if !sessionsDef {
						if c.IsAdmin {
							c.Manager = ipUser
							term = false
						}
					}
				} else {
					c.Manager = admins
					term = false
				}
			},
		},
		{
			Renew,
			func() {
				_, secretOk := c.Object[secretOkK] // FIXME a way to know
				// defined fields
				if !secretOk {
					c.Manager = crypt
				}
			},
		},
		{
			check,
			func() {
				v, secretOk := c.Object[secretOkK]
				_, userOk := c.Object[userK]
				if secretOk && userOk {
					c.Ok = c.User == v.(string)
				} else if !secretOk {
					c.Cmd = decrypt
					c.Manager = crypt
				} else if !userOk {
					c.Cmd = Get
					c.Manager = ipUserK
				}
			},
		},
		{
			Match,
			func() {
				_, userOk := c.Object[userK]
				if !userOk {
					c.Manager = ipUserK
					c.Cmd = Get
				} else {
					c.Ok = c.User != ""
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
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

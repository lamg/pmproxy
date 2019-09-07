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

type sessionIPM struct {
	Name string
	Auth string
}

const (
	Open        = "open"
	Close       = "close"
	Auth        = "authenticate"
	Check       = "check"
	SessionIPMK = "sessionIPM"
)

func (m *sessionIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Open,
			func() {
				if c.User == "" {
					c.Manager = m.Auth
					c.Cmd = Auth
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
				ok := c.defined(secretOk)
				if ok && c.Err == nil {
					c.Manager = cryptMng
					c.Cmd = decrypt
				} else if ok {
					c.Manager = ipUserMng
					c.Cmd = ipUserDel
				}
			},
		},
		{
			Get,
			func() {
				admDef := c.defined(isAdminK)
				if admDef {
					sessionsDef := c.defined(sessionsK)
					if !sessionsDef {
						if c.IsAdmin {
							c.Manager = ipUserMng
							term = false
						}
					}
				} else {
					c.Manager = adminsMng
					term = false
				}
			},
		},
		{
			Renew,
			func() {
				ok := c.defined(secretOk)
				if !ok {
					c.Manager = cryptMng
				}
			},
		},
		{
			Check,
			func() {
				secretOk := c.defined(secretOk)
				userOk := c.defined(userK)
				if secretOk && userOk {
					c.Ok = c.User == c.String
				} else if !secretOk {
					c.Cmd = decrypt
					c.Manager = cryptMng
				} else if !userOk {
					c.Cmd = Get
					c.Manager = ipUserMng
				}
			},
		},
		{
			Match,
			func() {
				term = c.defined(userK)
				if !term {
					c.Manager = ipUserMng
					c.Cmd = Get
				} else {
					c.Ok = c.User != ""
					c.interp[m.Name] = &MatchType{
						Type:  SessionIPMK,
						Match: c.Ok,
					}
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

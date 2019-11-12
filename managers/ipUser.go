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
	"sync"
)

type ipUser struct {
	mäp *sync.Map
}

func newIpUser() (s *ipUser) {
	s = &ipUser{
		mäp: new(sync.Map),
	}
	return
}

func (p *ipUser) exec(c *Cmd) {
	if c.internal {
		kf := []alg.KFunc{
			{
				Get,
				func() { c.loggedBy, _ = p.get(c.ip) },
			},
			{
				Open,
				func() { p.open(c.ip, c.loggedBy) },
			},
			{
				Close,
				func() { p.del(c.ip) },
			},
		}
		alg.ExecF(kf, c.Cmd)
	} else {
		c.err = &ManagerErr{Mng: c.Manager, Cmd: c.Cmd}
	}
}

type userAuth struct {
	user string
	auth string
}

func (p *ipUser) open(ip string, loggedBy *userAuth) {
	var oldIP string
	p.mäp.Range(func(k, v interface{}) (cont bool) {
		cont = v.(*userAuth).user != loggedBy.user
		if !cont {
			oldIP = k.(string)
		}
		return
	})
	if oldIP != "" {
		p.mäp.Delete(oldIP)
	}
	p.mäp.Store(ip, loggedBy)
}

func (p *ipUser) get(ip string) (loggedBy *userAuth,
	ok bool) {
	v, ok := p.mäp.Load(ip)
	if ok {
		loggedBy = v.(*userAuth)
	} else {
		loggedBy = new(userAuth)
	}
	return
}

func (p *ipUser) del(ip string) {
	p.mäp.Delete(ip)
	return
}

func (p *ipUser) set(ip, user string) {
	p.mäp.Store(ip, user)
}

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
	"sync"
)

const (
	ipUserMng = "ipUserMng"
	ipUserCmd = "ipUserCmd"
	ipUserDel = "ipUserDel"
	sessionsK = "sessions"
	userK     = "user"
	openedK   = "opened"
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

func (p *ipUser) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				var ok bool
				c.User, ok = p.get(c.IP)
				if !ok {
					c.Err = fmt.Errorf("Not logged user at '%s'", c.IP)
				}
			},
		},
		{
			Open,
			func() {
				p.open(c.IP, c.User)
			},
		},
		{
			Close,
			func() {
				p.del(c.IP)
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func (p *ipUser) open(ip, user string) {
	var oldIP string
	p.mäp.Range(func(k, v interface{}) (cont bool) {
		cont = v.(string) != user
		return
	})
	if oldIP != "" {
		p.mäp.Delete(oldIP)
	}
	p.mäp.Store(ip, user)
}

func (p *ipUser) get(ip string) (user string, ok bool) {
	v, ok := p.mäp.Load(ip)
	if ok {
		user = v.(string)
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
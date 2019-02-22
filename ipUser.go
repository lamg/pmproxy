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
	"sync"
)

type ipUserS struct {
	mäp *sync.Map
}

type ipUser func(string) (string, bool)

func newIPuserS() (s *ipUserS) {
	s = &ipUserS{
		mäp: new(sync.Map),
	}
	return
}

func (p *ipUserS) get(ip string) (user string, ok bool) {
	v, ok := p.mäp.Load(ip)
	if ok {
		user = v.(string)
	}
	return
}

func (p *ipUserS) del(ip string) {
	p.mäp.Delete(ip)
	return
}

func (p *ipUserS) set(ip, user string) {
	p.mäp.Store(ip, user)
}

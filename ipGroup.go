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

type ipGroupS struct {
	ipUser     ipUser
	userGroupN string
	userGroup  func(string) (userGroup, bool)
}

type ipGroup func(string) ([]string, error)

func (p *ipGroupS) get(ip string) (gs []string, e error) {
	var user string
	var ok bool
	var grp userGroup
	fs := []func(){
		func() { user, ok = p.ipUser(ip) },
		func() { grp, ok = p.userGroup(p.userGroupN) },
		func() { gs, e = grp(user) },
	}
	trueFF(fs, func() bool { return ok && e == nil })
	return
}

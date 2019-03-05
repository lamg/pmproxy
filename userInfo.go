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

type userInfo struct {
	iu       ipUser
	userName func(string) (string, error)
	quota    ipQuota
	isAdm    func(string) bool
}

type cmdInfo struct {
	UserName   string `json: "userName"`
	Name       string `json: "name"`
	IsAdmin    bool   `json: "isAdmin"`
	QuotaGroup uint64 `json: "quotaGroup"`
}

func (u *userInfo) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				user, _ := u.iu(c.RemoteAddr)
				inf := &cmdInfo{
					UserName:   user,
					IsAdmin:    u.isAdm(user),
					QuotaGroup: u.quota(c.RemoteAddr),
				}
				fs := []func(){
					func() { inf.Name, c.e = u.userName(user) },
					func() { c.bs, c.e = json.Marshal(inf) },
				}
				trueFF(fs, func() bool { return c.e == nil })
			},
		},
	}
	return
}

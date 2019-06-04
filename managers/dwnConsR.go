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
	"github.com/c2h5oh/datasize"
	alg "github.com/lamg/algorithms"
	"strings"
	"sync"
	"time"
)

type dwnConsR struct {
	name        string
	userDBN     string
	spec        *spec
	quotaCache  *sync.Map
	groupQuotaM *sync.Map

	userCons   *sync.Map
	lastReset  time.Time
	resetCycle time.Duration
}

const (
	groupsK = "groups"
	adminsK = "admins"
)

func (d *dwnConsR) managerKF(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				ok := c.defined(groupsK)
				var data *UserInfo
				if ok {
					data, c.Err = d.info(c.User, c.String, c.Groups)
					if c.Err == nil {
						c.Data, c.Err = json.Marshal(data)
					}
				} else {
					c.Manager = d.userDBN
				}
				term = ok
			},
		},
		{
			Set,
			func() {
				ok := c.defined(adminsK)
				if !ok {
					c.Manager, c.Cmd = adminsK, isAdminK
				} else if c.IsAdmin {
					d.userCons.Store(c.String, c.Uint64)
				}
			},
		},
		{
			Show,
			func() {
				c.Data, c.Err = json.Marshal(d)
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func (d *dwnConsR) keepResetCycle() {
	// this method maintains the property that if the current
	// time is greater or equal to d.lastReset + d.resetCycle,
	// then all consumptions are set to 0
	now := time.Now()
	cy := now.Sub(d.lastReset)
	if cy >= d.resetCycle {
		d.userCons = new(sync.Map)
		d.lastReset = d.lastReset.Add(d.resetCycle)
	}
}

func (d *dwnConsR) quota(user string, gs []string) (n uint64) {
	v, ok := d.quotaCache.Load(user)
	if ok {
		n = v.(uint64)
	} else {
		inf := func(i int) {
			q := d.groupQuota(gs[i])
			n = n + q
		}
		alg.Forall(inf, len(gs))
		d.quotaCache.Store(user, n)
	}
	return
}

func (d *dwnConsR) groupQuota(g string) (q uint64) {
	v, ok := d.groupQuotaM.Load(g)
	if ok {
		q = v.(uint64)
	}
	return
}

type UserInfo struct {
	Quota       string   `json:"quota"`
	Groups      []string `json:"groups"`
	Name        string   `json:"name"`
	UserName    string   `json:"userName"`
	Consumption string   `json:"consumption"`
	BytesQuota  uint64   `json:"bytesQuota"`
	BytesCons   uint64   `json:"bytesCons"`
}

func (d *dwnConsR) info(user, name string, gs []string) (
	ui *UserInfo, e error) {
	n := d.quota(user, gs)
	q := datasize.ByteSize(n).HumanReadable()
	ui = &UserInfo{
		Quota:      q,
		UserName:   user,
		BytesQuota: n,
		Groups:     gs,
		Name:       name,
	}
	v, ok := d.userCons.Load(user)
	var cons datasize.ByteSize
	if ok {
		cons = datasize.ByteSize(v.(uint64))
	}
	ui.Consumption = cons.HumanReadable()
	ui.BytesCons = uint64(cons)
	return
}

func cleanHumanReadable(hr string) (cl string) {
	cl = strings.Replace(hr, ".0", "", -1)
	return
}

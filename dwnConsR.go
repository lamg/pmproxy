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
	"sync"
	"time"
)

type dwnConsR struct {
	name       string
	userQuotaN string
	userQuota  func(string) uint64

	userCons   *sync.Map
	lastReset  time.Time
	resetCycle time.Duration
	mapWriter  func(map[string]uint64)
	fileReader func(string) ([]byte, error)
}

func (d *dwnConsR) fromMap(i interface{}) (e error) {
	fe := func(err error) { e = err }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.name = stringE(i, fe)
			},
		},
		{
			userQuotaK,
			func(i interface{}) {
				d.userQuotaN = stringE(i, fe)
			},
		},
		{
			lastResetK,
			func(i interface{}) {
				d.lastReset = stringDateE(i, fe)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				d.resetCycle = durationE(i, fe)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				d.userCons = new(sync.Map)
				var mp map[string]uint64
				var ne error
				var bs []byte
				fs := []func(){
					func() { bs, ne = d.fileReader(d.name + ".json") },
					func() { ne = json.Unmarshal(bs, &mp) },
					func() {
						for k, v := range mp {
							d.userCons.Store(k, v)
						}
					},
				}
				trueFF(fs, func() bool { return ne == nil })
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (d *dwnConsR) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		nameK:       d.name,
		userQuotaK:  d.userQuotaN,
		lastResetK:  d.lastReset.Format(time.RFC3339),
		resetCycleK: d.resetCycle.String(),
	}
	mp := make(map[string]uint64)
	d.userCons.Range(func(k, v interface{}) (b bool) {
		ks, vu := k.(string), v.(uint64)
		mp[ks] = vu
		return
	})
	d.mapWriter(mp)
	return
}

type qtCs struct {
	Quota       uint64 `json: "quota"`
	Consumption uint64 `json: "consumption"`
}

func (d *dwnConsR) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				if c.String != "" && c.IsAdmin {
					v, ok := d.userCons.Load(c.String)
					var n uint64
					if ok {
						n = v.(uint64)
					}
					c.bs, c.e = json.Marshal(n)
				} else {
					qc := &qtCs{
						Quota: d.userQuota(c.User),
					}
					v, ok := d.userCons.Load(c.User)
					if ok {
						qc.Consumption = v.(uint64)
					}
					c.bs, c.e = json.Marshal(qc)
				}
			},
		},
		{
			set,
			func() {
				if c.IsAdmin {
					d.userCons.Store(c.String, c.Uint64)
				}
			},
		},
	}
	return
}

func (d *dwnConsR) consR() (c *consR) {
	c = &consR{
		open: func(ip, user string) (ok bool) {
			// the reset cycle property is maintained on demand,
			// rather than at regular time lapses
			d.keepResetCycle()
			cons := uint64(0)
			d.userCons.LoadOrStore(user, cons)
			return
		},
		can: func(ip, user string, down int) (ok bool) {
			cons, b := d.userCons.Load(user)
			limit := d.userQuota(user)
			ok = b && cons.(uint64) <= limit
			return
		},
		update: func(ip, user string, down int) {
			v, _ := d.userCons.Load(user)
			cons := v.(uint64)
			d.userCons.Store(user, cons+uint64(down))
		},
		close: func(ip, user string) {},
	}
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

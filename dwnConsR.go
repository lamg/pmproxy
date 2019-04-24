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
	"github.com/c2h5oh/datasize"
	"strings"
	"sync"
	"time"
)

type dwnConsR struct {
	name        string
	userDBN     string
	userGroup   func(string) ([]string, error)
	userName    func(string) (string, error)
	spec        *spec
	quotaCache  *sync.Map
	groupQuotaM *sync.Map

	userCons   *sync.Map
	lastReset  time.Time
	resetCycle time.Duration
	mapWriter  func(map[string]uint64)
	fileReader func(string) ([]byte, error)
	warning    func(string) error
}

func (d *dwnConsR) fromMap(i interface{}) (e error) {
	fe := func(err error) { e = err }
	var m map[string]string
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.name = stringE(i, fe)
			},
		},
		{
			userDBK,
			func(i interface{}) {
				d.userDBN = stringE(i, fe)
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
				if ne != nil {
					d.warning("dwnConsR reading consumption:" + ne.Error())
				}
			},
		},
		{
			specKS,
			func(i interface{}) {
				d.spec = new(spec)
				d.spec.fromMap(i)
			},
		},
		{
			quotaMapK,
			func(i interface{}) {
				m = stringMapStringE(i, fe)
			},
		},
		{
			quotaMapK,
			func(i interface{}) {
				d.groupQuotaM = new(sync.Map)
				d.quotaCache = new(sync.Map)
				for k, v := range m {
					bts := new(datasize.ByteSize)
					nv := cleanHumanReadable(v)
					e = bts.UnmarshalText([]byte(nv))
					if e != nil {
						break
					}
					d.groupQuotaM.Store(k, bts.Bytes())
				}
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (d *dwnConsR) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		nameK:       d.name,
		userDBK:     d.userDBN,
		lastResetK:  d.lastReset.Format(time.RFC3339),
		resetCycleK: d.resetCycle.String(),
		specKS:      d.spec.toMap(),
		quotaMapK: func() (m map[string]string) {
			m = make(map[string]string)
			d.groupQuotaM.Range(func(k, v interface{}) (ok bool) {
				sz := datasize.ByteSize(v.(uint64))
				m[k.(string)], ok = sz.HumanReadable(), true
				return
			})
			return
		}(),
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

func (d *dwnConsR) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				var data *userInfo
				if c.IsAdmin && c.String != "" {
					data, c.e = d.info(c.String)
				} else {
					data, c.e = d.info(c.User)
				}
				if c.e == nil {
					c.bs, c.e = json.Marshal(data)
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
		{
			show,
			func() {
				c.bs, c.e = json.Marshal(d.toMap())
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
			ok = true
			return
		},
		can: func(ip, user string, down int) (ok bool) {
			cons, b := d.userCons.Load(user)
			limit := d.quota(user)
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

func (d *dwnConsR) quota(user string) (n uint64) {
	v, ok := d.quotaCache.Load(user)
	if ok {
		n = v.(uint64)
	} else {
		gs, _ := d.userGroup(user)
		inf := func(i int) {
			q := d.groupQuota(gs[i])
			n = n + q
		}
		forall(inf, len(gs))
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

type userInfo struct {
	Quota       string   `json:"quota"`
	Groups      []string `json:"groups"`
	Name        string   `json:"name"`
	UserName    string   `json:"userName"`
	Consumption string   `json:"consumption"`
}

func (d *dwnConsR) info(user string) (ui *userInfo, e error) {
	n := d.quota(user)
	q := datasize.ByteSize(n).HumanReadable()
	ui = &userInfo{
		Quota:    q,
		UserName: user,
	}
	ui.Groups, _ = d.userGroup(user)
	ui.Name, e = d.userName(user)
	v, ok := d.userCons.Load(user)
	var cons datasize.ByteSize
	if ok {
		cons = datasize.ByteSize(v.(uint64))
	}
	ui.Consumption = cons.HumanReadable()
	return
}

func cleanHumanReadable(hr string) (cl string) {
	cl = strings.Replace(hr, ".0", "", -1)
	return
}

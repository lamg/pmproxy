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
	"github.com/spf13/afero"
	"path"
	"strings"
	"sync"
	"time"
)

type DwnConsR struct {
	Name       string            `toml:"name"`
	UserDBN    string            `toml:"userDBN"`
	ResetCycle time.Duration     `toml:"resetCycle"`
	GroupQuota map[string]string `toml:"groupQuota"`

	lastReset time.Time

	mapPath     string
	fs          afero.Fs
	quotaCache  *sync.Map
	groupQuotaM *sync.Map

	userCons *sync.Map

	now func() time.Time
}

type consMap struct {
	LastReset    time.Time         `json:"lastReset"`
	Consumptions map[string]uint64 `json:"consumptions"`
}

func (d *DwnConsR) init(fs afero.Fs, pth string) (e error) {
	d.quotaCache, d.groupQuotaM, d.userCons = new(sync.Map),
		new(sync.Map), new(sync.Map)
	d.mapPath, d.fs = path.Join(pth, d.Name+".json"), fs
	bs, re := afero.ReadFile(fs, d.mapPath)
	if re == nil {
		cons := new(consMap)
		f := []func(){
			func() { e = json.Unmarshal(bs, &cons) },
			func() {
				d.lastReset = cons.LastReset
				for k, v := range cons.Consumptions {
					d.userCons.Store(k, v)
				}
			},
		}
		alg.TrueFF(f, func() bool { return e == nil })
	}
	if e == nil {
		for k, v := range d.GroupQuota {
			var bz datasize.ByteSize
			e = bz.UnmarshalText([]byte(v))
			if e == nil {
				d.groupQuotaM.Store(k, uint64(bz))
			} else {
				break
			}
		}
	}
	return
}

func (d *DwnConsR) persist() (e error) {
	d.keepResetCycle()
	cons := &consMap{
		Consumptions: make(map[string]uint64),
		LastReset:    d.lastReset,
	}
	d.userCons.Range(func(k, v interface{}) (ok bool) {
		cons.Consumptions[k.(string)], ok = v.(uint64), true
		return
	})
	bs, e := json.Marshal(cons)
	if e == nil {
		e = afero.WriteFile(d.fs, d.mapPath, bs, 0644)
	}
	return
}

func (d *DwnConsR) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				c.err = d.info(c.Info)
				if c.err == nil {
					c.data, c.err = json.Marshal(c.Info)
				}
			},
		},
		{
			GetOther,
			func() {
				if c.isAdmin {
					c.err = d.info(c.Info)
					if c.err == nil {
						c.data, c.err = json.Marshal(c.Info)
					}
				} else {
					c.err = &NoAdmErr{User: c.loggedBy.user}
				}
			},
		},
		{
			Set,
			func() {
				if c.isAdmin {
					d.userCons.Store(c.Info.UserName, c.Info.BytesCons)
				} else {
					c.err = &NoAdmErr{User: c.loggedBy.user}
				}
			},
		},
		{
			Show,
			func() {
				c.data, c.err = json.Marshal(d)
			},
		},
		{
			readRequest,
			func() {
				ok := d.filter(c)
				if ok {
					qt := d.quota(c.loggedBy.user, c.Info.Groups)
					cs := d.consumption(c.loggedBy.user)
					if cs >= qt {
						hcs := datasize.ByteSize(cs)
						c.err = &QuotaReachedErr{
							Quota: hcs.HumanReadable(),
						}
					}
				}
			},
		},
		{
			readReport,
			func() {
				ok := d.filter(c)
				if ok {
					cs := d.consumption(c.loggedBy.user)
					ncs := cs + c.Info.BytesCons
					d.userCons.Store(c.loggedBy.user, ncs)
				}
			},
		},
		{
			Match,
			func() {
				c.interp[d.Name] = &MatchType{Match: true, Type: DwnConsRK}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
}

func (d *DwnConsR) filter(c *Cmd) (ok bool) {
	// filter is run previous to readRequest or readReport
	// to indicate if this manager is suppossed to handle the
	// sent command. This changes since each connection has
	// a different consR assigned to it
	ok, _ = alg.BLnSrch(
		func(i int) bool { return c.consR[i] == d.Name },
		len(c.consR),
	)
	return
}

func (d *DwnConsR) consumption(user string) (n uint64) {
	v, ok := d.userCons.Load(user)
	if ok {
		n = v.(uint64)
	}
	return
}

func (d *DwnConsR) keepResetCycle() {
	// this method maintains the property that if the current
	// time is greater or equal to d.lastReset + d.resetCycle,
	// then all consumptions are set to 0
	now := d.now()
	cy := now.Sub(d.lastReset)
	if cy >= d.ResetCycle {
		tms := cy / d.ResetCycle
		d.userCons = new(sync.Map)
		d.lastReset = d.lastReset.Add(tms * d.ResetCycle)
	}
}

func (d *DwnConsR) quota(user string, gs []string) (n uint64) {
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

func (d *DwnConsR) groupQuota(g string) (q uint64) {
	v, ok := d.groupQuotaM.Load(g)
	if ok {
		q = v.(uint64)
	}
	return
}

func (d *DwnConsR) info(inf *UserInfo) (e error) {
	inf.BytesQuota = d.quota(inf.UserName, inf.Groups)
	inf.Quota = datasize.ByteSize(inf.BytesQuota).HumanReadable()
	inf.BytesCons = d.consumption(inf.UserName)
	inf.Consumption = datasize.ByteSize(inf.BytesCons).HumanReadable()
	return
}

func cleanHumanReadable(hr string) (cl string) {
	cl = strings.Replace(hr, ".0", "", -1)
	return
}

func (d *DwnConsR) paths() (ms []mngPath) {
	ms = []mngPath{
		{
			name: d.Name,
			cmd:  Get,
			mngs: []mngPath{
				{name: adminsMng, cmd: Protect},
				{name: ipUserMng, cmd: Get},
				{name: cryptMng, cmd: Check},
				{name: d.UserDBN, cmd: Get},
				{name: adminsMng, cmd: Get},
				{name: d.Name, cmd: Get},
			},
		},
		{
			name: d.Name,
			cmd:  GetOther,
			mngs: []mngPath{
				{name: adminsMng, cmd: Protect},
				{name: ipUserMng, cmd: Get},
				{name: cryptMng, cmd: Check},
				{name: d.UserDBN, cmd: GetOther},
				{name: adminsMng, cmd: Get},
				{name: adminsMng, cmd: isAdmin},
				{name: d.Name, cmd: GetOther},
			},
		},
		{
			name: d.Name,
			cmd:  Set,
			mngs: []mngPath{
				{name: adminsMng, cmd: Protect},
				{name: ipUserMng, cmd: Get},
				{name: cryptMng, cmd: Check},
				{name: adminsMng, cmd: isAdmin},
				{name: d.Name, cmd: Set},
			},
		},
		{
			name: d.Name,
			cmd:  Show,
			mngs: []mngPath{{name: d.Name, cmd: Show}},
		},
	}
	return
}

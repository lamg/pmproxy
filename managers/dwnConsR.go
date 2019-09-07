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
	"fmt"
	"github.com/c2h5oh/datasize"
	alg "github.com/lamg/algorithms"
	"github.com/lamg/proxy"
	"github.com/spf13/afero"
	"path"
	"strings"
	"sync"
	"time"
)

type dwnConsR struct {
	Name       string        `toml:"name"`
	UserDBN    string        `toml:"userDBN"`
	ResetCycle time.Duration `toml:"resetCycle"`

	lastReset time.Time

	mapPath     string
	fs          afero.Fs
	quotaCache  *sync.Map
	groupQuotaM *sync.Map

	userCons *sync.Map
}

const (
	DwnConsRK = "dwnConsR"
)

type consMap struct {
	LastReset    time.Time         `json:"lastReset"`
	Consumptions map[string]uint64 `json:"consumptions"`
}

func (d *dwnConsR) init(fs afero.Fs, pth string) (e error) {
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
	return
}

func (d *dwnConsR) persist() (e error) {
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

func (d *dwnConsR) exec(c *Cmd) (term bool) {
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
					c.Manager = d.UserDBN
				}
				term = ok
			},
		},
		{
			Set,
			func() {
				ok := c.defined(isAdminK)
				if !ok {
					c.Manager, c.Cmd = adminsMng, isAdminK
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
		{
			HandleConn,
			func() {
				term, c.Result = true, new(proxy.Result)
				if !c.defined(groupsK) {
					c.Manager, c.Cmd, term = ipUserMng, Get, false
				} else if c.Operation.Command == proxy.ReadRequest {
					qt := d.quota(c.User, c.Groups)
					cs := d.consumption(c.User)
					if cs >= qt {
						c.Result.Error = fmt.Errorf(
							"Consumption reached quota %d", cs)
					}
				} else if c.Operation.Command == proxy.ReadReport {
					cs := d.consumption(c.User)
					ncs := cs + c.Uint64
					d.userCons.Store(c.User, ncs)
				}
			},
		},
		{
			Match,
			func() {
				c.interp[d.Name], c.consR =
					&MatchType{Match: true, Type: DwnConsRK},
					append(c.consR, d.Name)
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func (d *dwnConsR) consumption(user string) (n uint64) {
	v, ok := d.userCons.Load(user)
	if ok {
		n = v.(uint64)
	}
	return
}

func (d *dwnConsR) keepResetCycle() {
	// this method maintains the property that if the current
	// time is greater or equal to d.lastReset + d.resetCycle,
	// then all consumptions are set to 0
	now := time.Now()
	cy := now.Sub(d.lastReset)
	if cy >= d.ResetCycle {
		d.userCons = new(sync.Map)
		d.lastReset = d.lastReset.Add(d.ResetCycle)
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
	ui.BytesCons = d.consumption(user)
	ui.Consumption = datasize.ByteSize(ui.BytesCons).HumanReadable()
	return
}

func cleanHumanReadable(hr string) (cl string) {
	cl = strings.Replace(hr, ".0", "", -1)
	return
}

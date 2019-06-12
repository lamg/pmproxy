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

/*
# Download consupmtion restrictor

The _Download consumption restrictor_ is a manager that limits the amount of data that users can download in determined period of time. It's implemented by `dwnConsR`. The fields `lastReset` and `resetCycle` determine the date when all consumptions in `userCons` are set to 0. `resetCycle` is the duration of the period, and `lastReset` is the date of the last reset, which is updated everytime consumptions are reseted. When a consumption reaches the assigned quota for that period of time, the manager notifies it through its interface.

The interface for interacting with it is the `exec` method, which receives a command (`Cmd`) and processes it. Commands may be received without the information needed to be processed, in that case the method `exec` changes the field `Cmd.Manager` to have the name of the manager that can provide the absent information. Then the method `manager.exec` deals with delivering that command to the right manager, and returning it back to the manager that originated it.

`dwnConsR` processes the following commands
- `Get` returns the user's alias and name, groups, quota and consumption. In case the command doesn't have field `Cmd.Groups` defined it will change the manager to the value of `dwnConsR.userDBN`, which is expected to set it according to the user logged at Cmd.IP.
- `Set` sets the value of `Cmd.Uint64` as the consumption for the user sent at `Cmd.String`, if the command is sent by an administrator. If the value for `Cmd.IsAdmin` isn't defined it will change the manager for `adminsK` which is the one that has the administrators stored.
- `Show` serializes with JSON format the `dwnConsR` instance, writing it to Cmd.Data
- `HandleConn` sets `Cmd.Ok` meaning if is possible continue with the connection operation sent in `Cmd.Operation`. When the operation is `proxy.ReadRequest`, the requested amount of bytes by the connection in the proxy comes in `Cmd.Uint64`
*/

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
	LastReset  time.Time     `toml:"lastReset"`
	ResetCycle time.Duration `toml:"resetCycle"`

	quotaCache  *sync.Map
	groupQuotaM *sync.Map

	userCons *sync.Map
}

func (d *dwnConsR) init(pth string, fs afero.Fs) (e error) {
	d.quotaCache, d.groupQuotaM, d.userCons = new(sync.Map),
		new(sync.Map), new(sync.Map)
	bs, e := afero.ReadFile(fs, path.Join(pth, d.Name+".json"))
	var cons map[string]uint64
	f := []func(){
		func() { e = json.Unmarshal(bs, &cons) },
		func() {
			for k, v := range cons {
				d.userCons.Store(k, v)
			}
		},
	}
	alg.TrueFF(f, func() bool { return e == nil })
	return
}

const (
	groupsK = "groups"
	adminsK = "admins"
)

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
			match,
			func() {
				c.interp[d.Name], c.consR = true, append(c.consR, d.Name)
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
	cy := now.Sub(d.LastReset)
	if cy >= d.ResetCycle {
		d.userCons = new(sync.Map)
		d.LastReset = d.LastReset.Add(d.ResetCycle)
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

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
	"github.com/lamg/proxy"
	"sync"
)

type manager struct {
	mngs *sync.Map
}

type Cmd struct {
	Cmd       string           `json:"cmd"`
	User      string           `json:"user"`
	Manager   string           `json:"manager"`
	Secret    string           `json:"secret"`
	IsAdmin   bool             `json:"isAdmin"`
	Cred      *Credentials     `json:"cred"`
	String    string           `json:"string"`
	Uint64    uint64           `json:"uint64"`
	Groups    []string         `json:"groups"`
	Ok        bool             `json:"ok"`
	IP        string           `json:"ip"`
	Data      []byte           `json:"data"`
	Err       error            `json:"-"`
	Operation *proxy.Operation `json:"-"`
	Result    *proxy.Result    `json:"-"`

	interp  map[string]bool
	consR   []string
	defKeys []string
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (c *Cmd) defined(key string) (ok bool) {
	ib := func(i int) bool { return c.defKeys[i] == key }
	ok, _ = alg.BLnSrch(ib, len(c.defKeys))
	return
}

type CmdF func(*Cmd) bool

func newManager(c *conf) (m *manager, e error) {
	m = &manager{mngs: new(sync.Map)}
	iu := newIpUser()
	cr, e := newCrypt(c.JWTExpiration)
	if e == nil {
		m.add(connectionsMng, newConnections().exec)
		m.add(ipUserMng, iu.exec)
		m.add(cryptMng, cr.exec)
	}
	return
}

func (m *manager) add(name string, f CmdF) {
	m.mngs.Store(name, f)
	return
}

const (
	Skip       = "skip"
	Get        = "get"
	Set        = "set"
	HandleConn = "handleConn"
	Show       = "show"
)

/*
	- each command when executed can be terminal or not. If not terminal,
	it means it must be executed by the manager now at Cmd.manager. If
	terminal it most be executed by the manager who originated it. Each
	manager must deal correctly with incoming and outgoing commands,
	according information present in them. The field Cmd.Object support
	storing and reading information produced by a sequence of executions.
*/

type mngCmd struct {
	mng string
	cmd string
}

func (m *manager) exec(c *Cmd) (proc bool) {
	var mngs []*mngCmd
	proc = true
	for (proc || len(mngs) != 0) && c.Err == nil {
		if proc {
			term, prev := m.execStep(c)
			if !term {
				mngs = append(mngs, prev)
			}
			proc = !term
		} else if len(mngs) != 0 {
			last := len(mngs) - 1
			next := mngs[last]
			mngs = mngs[:last]
			c.Manager = next.mng
			c.Cmd = next.cmd
			proc = true
		}
	}
	return
}

func (m *manager) execStep(c *Cmd) (term bool, prev *mngCmd) {
	v, ok := m.mngs.Load(c.Manager)
	prev = &mngCmd{mng: c.Manager, cmd: c.Cmd}
	if ok {
		term = v.(CmdF)(c)
	} else {
		c.Err = NoManager(c.Manager)
	}
	return
}

func NoManager(m string) (e error) {
	e = fmt.Errorf("manager '%s' not found", m)
	return
}

func (m *manager) delete(name string) (e error) {
	m.mngs.Delete(name)
	return
}

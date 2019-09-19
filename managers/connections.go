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
	"sync"
)

type connections struct {
	ipRestr *sync.Map
}

const (
	connectionsMng = "connections"
)

func newConnections() (c *connections) {
	c = &connections{ipRestr: new(sync.Map)}
	return
}

func (n *connections) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Open,
			func() {
				if c.Ok {
					n.ipRestr.Store(c.IP, c.consR)
				} else {
					c.Result.Error = fmt.Errorf("Rules evaluated to '%s'",
						c.String)
				}
			},
		},
		{
			Close,
			func() { n.ipRestr.Delete(c.IP) },
		},
		{
			HandleConn,
			func() {
				v, ok := n.ipRestr.Load(c.IP)
				if ok {
					c.consR = v.([]string)
				} else {
					c.Err = &NoConnErr{IP: c.IP}
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

type NoConnErr struct {
	IP string
}

func (c *NoConnErr) Error() (s string) {
	s = fmt.Sprintf("No connection at '%s'", c.IP)
	return
}

func connPaths(avlRestr, rulesDeps []mngPath) (ps []mngPath) {
	// depends on matching restrictors, and those are determined
	// after initialization, with a specific Cmd instance.
	// The solution is intercalating a Filter command for each
	// available restrictor, its dependencies and finally a
	// HandleConn command to each one.
	// The Filter command leaves in the Cmd instance a value of
	// true in Cmd.Ok if that restrictor is meant to handle that
	// connection
	avm := make([]mngPath, 1)
	avm[0] = mngPath{name: connectionsMng, cmd: HandleConn}
	for _, j := range avlRestr {
		avm = append(avm, mngPath{name: j.name, cmd: Filter})
		avm = append(avm, j.mngs...)
		avm = append(avm, mngPath{name: j.name, cmd: HandleConn})
	}
	ps = []mngPath{
		{
			name: connectionsMng,
			cmd:  Open,
			mngs: append(rulesDeps,
				mngPath{name: connectionsMng, cmd: Open}),
		},
		{
			name: connectionsMng,
			cmd:  Close,
			mngs: []mngPath{
				{name: connectionsMng, cmd: Close},
			},
		},
		{
			name: connectionsMng,
			cmd:  HandleConn,
			mngs: avm,
		},
	}
	return
}

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
	"github.com/lamg/proxy"
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

type restrCurr struct {
	restrictors []string
	current     int
}

func (n *connections) exec(c *Cmd) (term bool) {
	if c.Operation.Command == proxy.Open {
		if c.consR == nil && c.String == "" {
			c.Cmd, c.Manager = Match, RulesK
		} else {
			if c.Ok {
				rc := &restrCurr{restrictors: c.consR, current: 0}
				n.ipRestr.Store(c.Operation.IP, rc)
			} else {
				c.Result.Error = fmt.Errorf("Rules evaluated to: %s",
					c.String)
			}
			term = true
		}
	} else {
		v, ok := n.ipRestr.Load(c.Operation.IP)
		if ok {
			if c.Operation.Command == proxy.Close {
				n.ipRestr.Delete(c.Operation.IP)
			} else {
				rc := v.(*restrCurr)
				if rc.current == len(rc.restrictors) {
					term, rc.current = true, 0
				} else {
					c.Manager, c.Cmd = rc.restrictors[rc.current],
						HandleConn
				}
			}
		} else {
			c.Err = fmt.Errorf("No connection at %s", c.Operation.IP)
		}
	}
	return
}

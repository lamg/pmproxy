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
# Connections

Connections is a manager for handling the commands sent by the proxy, i.e. those with `Cmd.Operation` defined. When `Cmd.Operation.Command` is `proxy.Open` if there are no consumption restrictors set, then a match command is sent to get at the next call those consumption restrictors set. At that point a connection is added to the dictionary, with IP as key and consumption restrictors as value. The following commands on that connection are processed by sending commands to the consumption restrictors associated with its origin IP.
*/

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

const (
	restrictorsK = "restrictors"
	MatchersMng  = "matchers"
	match        = "match"
)

func (n *connections) exec(c *Cmd) (term bool) {
	if c.Operation.Command == proxy.Open {
		if !c.defined(restrictorsK) {
			c.Cmd, c.Manager = match, MatchersMng
		} else {
			rc := &restrCurr{restrictors: c.consR, current: 0}
			n.ipRestr.Store(c.Operation.IP, rc)
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

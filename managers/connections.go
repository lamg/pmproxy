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
	alg "github.com/lamg/algorithms"
	"sync"
)

type connections struct {
	ipRestr *sync.Map
	logger  *logger
}

func (n *connections) exec(c *Cmd) {
	loadConsR := func() {
		v, ok := n.ipRestr.Load(c.ip)
		if ok {
			c.consR = v.([]string)
		} else {
			c.err = &NoConnErr{IP: c.ip}
		}
	}
	kf := []alg.KFunc{
		{
			Open,
			func() {
				if c.ok {
					if c.Info.UserName == "" {
						c.Info.UserName = "-"
					}
					n.logger.log(c.rqp.Method, c.rqp.URL, c.ip,
						c.Info.UserName)
					n.ipRestr.Store(c.ip, c.consR)
				} else {
					c.err = &ForbiddenByRulesErr{Result: c.result}
				}
			},
		},
		{Close, func() { n.ipRestr.Delete(c.ip) }},
		{readRequest, loadConsR},
		{readReport, loadConsR},
	}
	alg.ExecF(kf, c.Cmd)
}

func connPaths(avlRestr, rulesDeps []mngPath) (ps []mngPath) {
	// depends on matching restrictors, and those are determined
	// after initialization, with a specific Cmd instance.
	// The solution is intercalating a Filter command for each
	// available restrictor, its dependencies and finally a
	// readRequest and readReport command to each one.
	// The Filter command leaves in the Cmd instance a value of
	// true in Cmd.Ok if that restrictor is meant to handle that
	// connection
	avmReadRequest, avmReadReport :=
		availableManagers(avlRestr, readRequest),
		availableManagers(avlRestr, readReport)
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
			cmd:  readRequest,
			mngs: avmReadRequest,
		},
		{
			name: connectionsMng,
			cmd:  readReport,
			mngs: avmReadReport,
		},
	}
	return
}

func availableManagers(avlRestr []mngPath,
	command string) (avm []mngPath) {
	avm = make([]mngPath, 1)
	avm[0] = mngPath{
		name: connectionsMng,
		cmd:  command,
	}
	for _, j := range avlRestr {
		avm = append(avm, j.mngs...)
		avm = append(avm, mngPath{name: j.name, cmd: command})
	}
	return
}

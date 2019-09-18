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
	mng "github.com/lamg/pmproxy/managers"
	"github.com/urfave/cli"
)

func (p *PMClient) ResetConsumption() (m cli.Command) {
	var dwn string
	m = cli.Command{
		Name:    "reset",
		Aliases: []string{"r"},
		Usage:   "Resets an user's consumption",
		Flags:   managerFlag(&dwn, ""),
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			li, e := p.readSecret()
			if e == nil {
				e = checkArgExec(
					func() error { return p.reset(li.DwnConsR, args[0]) },
					1,
					len(args),
				)
			}
			return
		},
	}
	return
}

func (p *PMClient) reset(manager, user string) (e error) {
	m := &mng.Cmd{
		Manager: manager,
		Cmd:     mng.Set,
		String:  user,
		Uint64:  1,
	}
	okf := func(bs []byte) (d error) { return }
	e = p.sendRecv(m, okf)
	return
}

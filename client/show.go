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

package client

import (
	"fmt"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/urfave/cli"
)

func (p *PMClient) ShowMng() (m cli.Command) {
	m = cli.Command{
		Name:    "show",
		Aliases: []string{"sh"},
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			e = checkArgExec(
				func() (d error) {
					r, d := p.showMng(args[0])
					fmt.Println(r)
					return
				},
				1,
				len(args),
			)
			return
		},
	}
	return
}

func (p *PMClient) showMng(manager string) (r string, e error) {
	m := &mng.Cmd{
		Manager: manager,
		Cmd:     mng.Show,
	}
	okf := func(bs []byte) (d error) { r = string(bs); return }
	e = p.sendRecv(m, okf)
	return
}

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
	"encoding/json"
	"fmt"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/urfave/cli"
)

func (p *PMClient) UserStatus() (m cli.Command) {
	var dwn string
	m = cli.Command{
		Name:    "status",
		Aliases: []string{"s"},
		Flags:   managerFlag(&dwn, ""),
		Usage:   "Retrieves user status",
		Action: func(c *cli.Context) (e error) {
			user, args := "", c.Args()
			// empty means the status is its own
			// otherwise if it's administrator it can get other
			// user's status
			if args.Present() {
				user = args.First()
			}
			ui, e := p.status(dwn, user)
			if e == nil {
				fmt.Printf("User: %s\n", ui.UserName)
				fmt.Printf("Name: %s\n", ui.Name)
				fmt.Printf("Groups: %v\n", ui.Groups)
				fmt.Printf("Quota: %s Consumption: %s\n", ui.Quota,
					ui.Consumption)
			}
			return
		},
	}
	return
}

func (p *PMClient) status(dwnMng, user string) (ui *mng.UserInfo, e error) {
	var li *loginInfo
	if dwnMng == "" {
		li, e = p.readSecret()
		if e == nil {
			dwnMng = li.DwnConsR
		}
	}
	if dwnMng != "" {
		m := &mng.Cmd{
			Cmd:     mng.Get,
			Manager: dwnMng,
		}
		if user != "" {
			m.Cmd = mng.GetOther
			m.Info = &mng.UserInfo{UserName: user}
		}
		okf := func(bs []byte) (d error) {
			ui = new(mng.UserInfo)
			d = json.Unmarshal(bs, ui)
			return
		}
		e = p.sendRecv(m, okf)
	} else if e == nil {
		m := &mng.Cmd{
			Cmd:     mng.Check,
			Manager: li.SessionIPM,
			Secret:  li.Secret,
		}
		okf := func(bs []byte) (d error) {
			ui = &mng.UserInfo{UserName: string(bs)}
			return
		}
		e = p.sendRecv(m, okf)
	}
	return
}

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
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/urfave/cli"
	"io/ioutil"
	h "net/http"
)

func (p *PMClient) Discover() (m cli.Command) {
	m = cli.Command{
		Name:    "discover",
		Aliases: []string{"d"},
		Usage: "Discover the resources you have available at the" +
			" proxy server, for some url (optional)",
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			var dr *mng.DiscoverRes
			if len(args) == 2 {
				dr, e = p.discoverC(args[0], args[1])
			} else if len(args) == 1 {
				dr, e = p.discoverC(args[0], "")
			} else if len(args) == 0 {
				dr, e = p.discoverC("", "")
			} else {
				e = checkArgExec(func() error { return nil }, 1,
					len(args))
			}
			if dr != nil {
				printDR(dr)
			}
			return
		},
	}
	return
}

func (p *PMClient) discoverC(url,
	remote string) (dr *mng.DiscoverRes, e error) {
	m := &mng.Cmd{
		Cmd:     mng.Discover,
		Manager: mng.RulesK,
		String:  remote,
	}
	var r *h.Response
	var bs []byte

	fs := []func(){
		func() {
			if url == "" {
				var li *loginInfo
				li, e = p.readSecret()
				if e == nil {
					url = li.Server
				}
			}
		},
		func() { r, e = p.PostCmd(url, m) },
		func() { bs, e = ioutil.ReadAll(r.Body) },
		func() {
			dr = new(mng.DiscoverRes)
			e = json.Unmarshal(bs, dr)
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
	return
}

func printDR(dr *mng.DiscoverRes) {
	fmt.Printf("Match result: %s\n", dr.Result)
	for k, v := range dr.MatchMng {
		var m string
		if v.Match {
			m = "✅"
		} else {
			m = "❌"
		}
		fmt.Printf("[%s] %s:%s\n", m, k, v.Type)
	}
}

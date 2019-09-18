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
	"github.com/spf13/afero"
	"github.com/urfave/cli"
	"io/ioutil"
	h "net/http"
)

func (p *PMClient) Login() (m cli.Command) {
	var sm string
	m = cli.Command{
		Name:    "login",
		Aliases: []string{"l"},
		Usage: "Open a session in PMProxy server, " +
			"given PMProxy address, user and password",
		Flags: managerFlag(&sm, ""),
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			e = checkArgExec(
				func() error {
					return p.login(args[0], sm, args[1], args[2])
				},
				3,
				len(args),
			)
			if e != nil &&
				e.Error() == fmt.Sprintf("No manager %s", sm) {
				// TODO discover
			}
			return
		},
	}
	return
}

type loginInfo struct {
	Server     string `json:"server"`
	SessionIPM string `json:"sessionIPM"`
	DwnConsR   string `json:"dwnConsR"`
	BwConsR    string `json:"bwConsR"`
	Secret     string `json:"secret"`
}

func (p *PMClient) login(urls, sm, user, pass string) (e error) {
	var li *loginInfo
	li, e = p.loginSM(urls, sm, user, pass)
	// try login at sm
	if e == nil {
		e = p.fillConsR(li)
	}
	if e == nil {
		e = p.writeSecret(li)
	}
	return
}

func (p *PMClient) fillConsR(li *loginInfo) (e error) {
	dr := new(mng.DiscoverRes)
	var bs []byte
	var r *h.Response
	fs := []func(){
		func() {
			m := &mng.Cmd{Manager: mng.RulesK, Cmd: mng.Match}
			r, e = p.PostCmd(li.Server, m)
		},
		func() { bs, e = ioutil.ReadAll(r.Body) },
		func() { e = json.Unmarshal(bs, dr) },
		func() {
			li.DwnConsR = matchMngType(dr, mng.DwnConsRK)
			li.BwConsR = matchMngType(dr, mng.BwConsRK)
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
	return
}

func matchMngType(dr *mng.DiscoverRes, tÿpe string) (name string) {
	for k, v := range dr.MatchMng {
		if v.Match && v.Type == tÿpe {
			name = k
			break
		}
	}
	return
}

func (p *PMClient) loginSM(urls, sm, user,
	pass string) (li *loginInfo,
	e error) {
	m := &mng.Cmd{
		Cred:    &mng.Credentials{User: user, Pass: pass},
		Manager: sm,
		Cmd:     mng.Open,
	}
	var r *h.Response
	fs := []func(){
		func() {
			r, e = p.PostCmd(urls, m)
		},
	}
	fe := func(d error) { e = d }
	okf := func(bs []byte) (d error) {
		li = &loginInfo{
			Server: urls, SessionIPM: sm, Secret: string(bs),
		}
		return
	}
	fs = append(fs,
		doOK(okf, fe, func() *h.Response { return r })...)
	alg.TrueFF(fs, func() bool { return e == nil })
	return
}

func (p *PMClient) writeSecret(li *loginInfo) (e error) {
	bs, e := json.Marshal(li)
	if e == nil {
		e = afero.WriteFile(p.Fs, loginSecretFile, bs, 0644)
	}
	return
}

func (p *PMClient) Logout() (m cli.Command) {
	var sm string
	m = cli.Command{
		Name:    "logout",
		Aliases: []string{"o"},
		Usage: "Closes the opened session in PMProxy server if" +
			" login.secret is found",
		Flags: managerFlag(&sm, ""),
		Action: func(c *cli.Context) (e error) {
			// TODO another user could be specified when logged as adm
			e = p.logout()
			return
		},
	}
	return
}

func (p *PMClient) logout() (e error) {
	m := &mng.Cmd{
		Cmd: mng.Close,
	}
	li, e := p.readSecret()
	if e == nil {
		m.Manager = li.SessionIPM
		okf := func(bs []byte) (d error) {
			d = p.Fs.Remove(loginSecretFile)
			return
		}
		e = p.sendRecv(m, okf)
	}
	return
}

func (p *PMClient) LoggedUsers() (m cli.Command) {
	var sm string
	m = cli.Command{
		Name:    "logged-users",
		Aliases: []string{"lu"},
		Flags:   managerFlag(&sm, ""),
		Action: func(c *cli.Context) (e error) {
			mp, e := p.loggedUsers(sm)
			if e == nil {
				fmt.Printf("ip - user\n")
				for k, v := range mp {
					fmt.Printf("%s - %s\n", k, v)
				}
			}
			return
		},
	}
	return
}

func (p *PMClient) loggedUsers(sm string) (mp map[string]string,
	e error) {
	if sm == "" {
		li, e := p.readSecret()
		if e == nil {
			sm = li.SessionIPM
		}
	}
	if sm == "" {
		e = fmt.Errorf("Unable to get sessionIPM")
	}
	if e == nil {
		m := &mng.Cmd{
			Cmd:     mng.Get,
			Manager: sm,
		}
		okf := func(bs []byte) (d error) {
			mp = make(map[string]string)
			d = json.Unmarshal(bs, &mp)
			return
		}
		e = p.sendRecv(m, okf)
	}
	return
}

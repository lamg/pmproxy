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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"github.com/urfave/cli"
	"io/ioutil"
	h "net/http"
	"os"
	"strings"
)

type PMClient struct {
	Fs      afero.Fs
	PostCmd func(string, *mng.Cmd) (*h.Response, error)
}

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
				e.Error() == mng.NoManager(sm).Error() {
				// TODO discover
			}
			return
		},
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

func (p *PMClient) UserStatus() (m cli.Command) {
	var dwn string
	m = cli.Command{
		Name:    "status",
		Aliases: []string{"s"},
		Flags:   managerFlag(&dwn, ""),
		Usage:   "Retrieves user status",
		Action: func(c *cli.Context) (e error) {
			ui, e := p.status(dwn)
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

func (p *PMClient) ShowMng() (m cli.Command) {
	m = cli.Command{
		Name:    "show",
		Aliases: []string{"sh"},
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			e = checkArgExec(
				func() (d error) {
					objT, d := p.showMng(args[0])
					if d == nil {
						enc := toml.NewEncoder(os.Stdout)
						e = enc.Encode(objT)
					}
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

func (p *PMClient) showMng(manager string) (objT *mng.ObjType,
	e error) {
	m := &mng.Cmd{
		Manager: mng.MatchersMng,
		Cmd:     mng.Get,
		String:  manager,
	}
	okf := func(bs []byte) (d error) {
		objT = new(mng.ObjType)
		d = json.Unmarshal(bs, objT)
		return
	}
	e = p.sendRecv(m, okf)
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

func (p *PMClient) discoverC(url,
	remote string) (dr *mng.DiscoverRes, e error) {
	m := &mng.Cmd{
		Cmd:     mng.Match,
		Manager: mng.MatchersMng,
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
		func() {
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
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

func (p *PMClient) status(dwnMng string) (ui *mng.UserInfo, e error) {
	if dwnMng == "" {
		var li *loginInfo
		li, e = p.readSecret()
		if e == nil {
			dwnMng = li.DwnConsR
		}
	}
	m := &mng.Cmd{
		Cmd:     mng.Get,
		Manager: dwnMng,
	}
	okf := func(bs []byte) (d error) {
		ui = new(mng.UserInfo)
		d = json.Unmarshal(bs, ui)
		return
	}
	e = p.sendRecv(m, okf)
	return
}

func (p *PMClient) sendRecv(m *mng.Cmd,
	okf func([]byte) error) (e error) {
	var li *loginInfo
	var r *h.Response
	fs := []func(){
		func() {
			li, e = p.readSecret()
		},
		func() {
			m.Secret = li.Secret
			r, e = p.PostCmd(li.Server, m)
			if e != nil && strings.HasPrefix(e.Error(),
				"token is expired") {
				nm := &mng.Cmd{
					Cmd:     mng.Renew,
					Manager: li.SessionIPM,
					Secret:  li.Secret,
				}
				var nr *h.Response
				var bs []byte
				fs0 := []func(){
					func() { nr, e = p.PostCmd(li.Server, nm) },
					func() { bs, e = ioutil.ReadAll(nr.Body) },
					func() {
						li.Secret = string(bs)
						m.Secret = li.Secret
						e = p.writeSecret(li)
					},
					func() { r, e = p.PostCmd(li.Server, m) },
				}
				alg.TrueFF(fs0, func() bool { return e == nil })
			}
		},
	}
	re := func(d error) { e = d }
	fs = append(fs, doOK(okf, re,
		func() *h.Response { return r })...)
	alg.TrueFF(fs, func() bool { return e == nil })
	return
}

func managerFlag(mng *string,
	dëfault string) (f []cli.Flag) {
	f = []cli.Flag{
		cli.StringFlag{
			Name:        "m",
			Usage:       "Manager for handling the command",
			Value:       dëfault,
			Destination: mng,
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
			m := &mng.Cmd{Manager: mng.MatchersMng, Cmd: mng.Match}
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

func (p *PMClient) writeSecret(li *loginInfo) (e error) {
	bs, e := json.Marshal(li)
	if e == nil {
		e = afero.WriteFile(p.Fs, loginSecretFile, bs, 0644)
	}
	return
}

func (p *PMClient) readSecret() (li *loginInfo, e error) {
	bs, e := afero.ReadFile(p.Fs, loginSecretFile)
	if e == nil {
		li = new(loginInfo)
		e = json.Unmarshal(bs, li)
	}
	return
}

func PostCmd(urls string, c *mng.Cmd) (r *h.Response, e error) {
	h.DefaultTransport.(*h.Transport).TLSClientConfig =
		&tls.Config{InsecureSkipVerify: true}
	h.DefaultTransport.(*h.Transport).Proxy = nil
	// TODO find a better place for the previous line
	bs, e := json.Marshal(c)
	if e == nil {
		buff := bytes.NewBuffer(bs)
		u := urls + ApiCmd
		r, e = h.Post(u, "text/json", buff)
		if e == nil && r.StatusCode == h.StatusBadRequest {
			bs, e = ioutil.ReadAll(r.Body)
			if e == nil {
				e = fmt.Errorf("%s", string(bs))
			}
		}
	}
	return
}

func doOK(ok func([]byte) error, fe func(error),
	fr func() *h.Response) (fs []func()) {
	var bs []byte
	var e error
	fs = []func(){
		func() {
			r := fr()
			bs, e = ioutil.ReadAll(r.Body)
			r.Body.Close()
			fe(e)
		},
		func() {
			r := fr()
			if r.StatusCode == h.StatusOK {
				e = ok(bs)
			} else {
				e = fmt.Errorf("%s", string(bs[:len(bs)-1])) //excluding EOL
			}
			fe(e)
		},
	}
	return
}

func checkArgExec(fe func() error, exp, act int) (e error) {
	if exp == act {
		e = fe()
	} else {
		e = fmt.Errorf("Invalid argument list length."+
			"Expected %d, got %d", exp, act)
	}
	return
}

const (
	loginSecretFile = "login.secret"
)

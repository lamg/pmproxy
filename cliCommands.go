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
	pred "github.com/lamg/predicate"
	"github.com/spf13/afero"
	"github.com/urfave/cli"
	"io/ioutil"
	h "net/http"
	"strings"
)

type PMClient struct {
	Fs      afero.Fs
	PostCmd func(string, *cmd) (*h.Response, error)
}

func (p *PMClient) Discover() (m cli.Command) {
	m = cli.Command{
		Name:    "discover",
		Aliases: []string{"d"},
		Usage: "Discover the resources you have available at the" +
			" proxy server, for some url (optional)",
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			var dr *discoverRes
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

func printDR(dr *discoverRes) {
	fmt.Printf("Match result: %s\n", pred.String(dr.Result))
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
			if e != nil && e.Error() == noKey(sm).Error() {
				p.filterSMs(args[0])
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
		Flags:   managerFlag(&dwn, defaultDwnConsR),
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			e = checkArgExec(
				func() error { return p.reset(dwn, args[0]) },
				1,
				len(args),
			)
			return
		},
	}
	return
}

func (p *PMClient) discoverC(url,
	remote string) (dr *discoverRes, e error) {
	m := &cmd{
		Cmd:     discover,
		Manager: resourcesK,
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
			dr = new(discoverRes)
			e = json.Unmarshal(bs, dr)
		},
		func() {
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (p *PMClient) reset(manager, user string) (e error) {
	m := &cmd{
		Manager: manager,
		Cmd:     set,
		String:  user,
		Uint64:  1,
	}
	okf := func(bs []byte) (d error) { return }
	e = p.sendRecv(m, okf)
	return
}

func (p *PMClient) status(dwnMng string) (ui *userInfo, e error) {
	if dwnMng == "" {
		var li *loginInfo
		li, e = p.readSecret()
		if e == nil {
			dwnMng = li.DwnConsR
		}
	}
	m := &cmd{
		Cmd:     get,
		Manager: dwnMng,
	}
	okf := func(bs []byte) (d error) {
		ui = new(userInfo)
		d = json.Unmarshal(bs, ui)
		return
	}
	e = p.sendRecv(m, okf)
	return
}

func (p *PMClient) sendRecv(m *cmd,
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
		},
	}
	re := func(d error) { e = d }
	fs = append(fs, doOK(okf, re,
		func() *h.Response { return r })...)
	p.handleRenew(fs, func() error { return e }, re)
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
	if sm == "" {
		ss := p.filterSMs(urls)
		if len(ss) != 0 {
			li, e = p.loginSM(urls, ss[0], user, pass)
		}
		if e != nil && len(ss) != 0 {
			e = fmt.Errorf("%s .Try one of %v", e.Error(), ss[1:])
		}
		// try login at first
	} else {
		li, e = p.loginSM(urls, sm, user, pass)
		// try login at sm
	}
	if e == nil {
		e = p.fillConsR(li)
	}
	if e == nil {
		e = p.writeSecret(li)
	}
	return
}

func (p *PMClient) fillConsR(li *loginInfo) (e error) {
	dr := new(discoverRes)
	var bs []byte
	var r *h.Response
	fs := []func(){
		func() {
			m := &cmd{Manager: resourcesK, Cmd: discover}
			r, e = p.PostCmd(li.Server, m)
		},
		func() { bs, e = ioutil.ReadAll(r.Body) },
		func() { e = json.Unmarshal(bs, dr) },
		func() {
			li.DwnConsR = matchMngType(dr, dwnConsRK)
			li.BwConsR = matchMngType(dr, bwConsRK)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func matchMngType(dr *discoverRes, tÿpe string) (name string) {
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
	m := &cmd{
		Cred:    &credentials{User: user, Pass: pass},
		Manager: sm,
		Cmd:     open,
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
	trueFF(fs, func() bool { return e == nil })
	return
}

func (p *PMClient) filterSMs(ürl string) (ss []string) {
	m := &cmd{
		Manager: resourcesK,
		Cmd:     filter,
		String:  sessionIPMK,
	}
	var r *h.Response
	var e error
	fe := func(d error) { e = d }
	fs := []func(){
		func() {
			r, e = p.PostCmd(ürl, m)
		},
	}
	ss = make([]string, 0)
	okf := func(bs []byte) (e error) {
		e = json.Unmarshal(bs, &ss)
		return
	}
	fs = append(fs,
		doOK(okf, fe, func() *h.Response { return r })...)
	trueFF(fs, func() bool { return e == nil })
	return
}

func (p *PMClient) logout() (e error) {
	m := &cmd{
		Cmd: clöse,
	}
	var r *h.Response
	var li *loginInfo
	fs := []func(){
		func() {
			li, e = p.readSecret()
		},
		func() {
			m.Secret, m.Manager = li.Secret, li.SessionIPM
			r, e = p.PostCmd(li.Server, m)
		},
	}
	fe := func(d error) { e = d }
	//only if error is "token exp..."
	okf := func(bs []byte) (d error) {
		d = p.Fs.Remove(loginSecretFile)
		return
	}
	fs = append(fs,
		doOK(okf, fe, func() *h.Response { return r })...)
	p.handleRenew(fs, func() error { return e }, fe)
	return
}

func (p *PMClient) handleRenew(fs []func(), re func() error,
	te func(error)) {
	rnw := func() {
		if re() != nil &&
			strings.HasPrefix(re().Error(), "token expired") {
			var li *loginInfo
			var r *h.Response
			fsn := []func(){
				func() {
					var e error
					li, e = p.readSecret()
					te(e)
				},
				func() {
					m := &cmd{
						Cmd:     renew,
						Manager: li.SessionIPM,
						Secret:  li.Secret,
					}
					var e error
					r, e = p.PostCmd(li.Server, m)
					te(e)
				},
			}
			okf := func(bs []byte) (d error) {
				li.Secret = string(bs)
				d = p.writeSecret(li)
				return
			}
			fsn = append(fsn, doOK(okf, te,
				func() *h.Response { return r })...)
			fsn = append(fsn, fs...)
			trueFF(fsn, func() bool { return re() == nil })
		}
	}
	trueFF(append(fs, rnw), func() bool { return re() == nil })
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

func PostCmd(urls string, c *cmd) (r *h.Response, e error) {
	h.DefaultTransport.(*h.Transport).TLSClientConfig =
		&tls.Config{InsecureSkipVerify: true}
	// TODO find a better place for the previous line
	bs, e := json.Marshal(c)
	if e == nil {
		buff := bytes.NewBuffer(bs)
		u := urls + apiCmd
		r, e = h.Post(u, "text/json", buff)
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

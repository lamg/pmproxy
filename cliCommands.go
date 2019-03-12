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
	"encoding/json"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/urfave/cli"
	"io/ioutil"
	h "net/http"
	"os"
	"strings"
)

func Login() (m cli.Command) {
	var sm string
	m = cli.Command{
		Name:    "login",
		Aliases: []string{"l"},
		Usage: "Open a session in PMProxy server, " +
			"given PMProxy address, user and password",
		Flags: managerFlag(&sm, defaultSessionIPM),
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			e = checkArgExec(
				func() error {
					return login(args[0], sm, args[1], args[2])
				},
				3,
				len(args),
			)
			return
		},
	}
	return
}

func Logout() (m cli.Command) {
	var sm string
	m = cli.Command{
		Name:    "logout",
		Aliases: []string{"o"},
		Usage: "Closes the opened session in PMProxy server if" +
			" login.secret is found",
		Flags: managerFlag(&sm, defaultSessionIPM),
		Action: func(c *cli.Context) (e error) {
			e = logout()
			return
		},
	}
	return
}

func UserStatus() (m cli.Command) {
	var dwn string
	m = cli.Command{
		Name:    "status",
		Aliases: []string{"s"},
		Flags:   managerFlag(&dwn, defaultDwnConsR),
		Usage:   "Retrieves user status",
		Action: func(c *cli.Context) (e error) {
			e = status(dwn)
			return
		},
	}
	return
}

func ResetConsumption() (m cli.Command) {
	var dwn string
	m = cli.Command{
		Name:    "reset",
		Aliases: []string{"r"},
		Usage:   "Resets an user's consumption",
		Flags:   managerFlag(&dwn, defaultDwnConsR),
		Action: func(c *cli.Context) (e error) {
			args := c.Args()
			checkArgExec(
				func() error { return reset(dwn, args[0]) },
				1,
				len(args),
			)
			return
		},
	}
	return
}

func UserInfo() (m cli.Command) {
	m = cli.Command{
		Name:    "info",
		Aliases: []string{"i"},
		Usage:   "Retrieves user information",
	}
	return
}

func reset(manager, user string) (e error) {
	// TODO
	return
}

func status(dwnMng string) (e error) {
	var li *loginInfo
	var r *h.Response
	fs := []func(){
		func() {
			li, e = readSecret()
		},
		func() {
			m := &cmd{
				Cmd:     get,
				Manager: dwnMng,
				Secret:  li.Secret,
			}
			r, e = postCmd(li.Server, m)
		},
	}
	re := func(d error) { e = d }
	okf := func(bs []byte) (d error) {
		qc := new(qtCs)
		d = json.Unmarshal(bs, qc)
		if d == nil {
			fmt.Sprintf("Quota: %s Consumption: %s\n",
				datasize.ByteSize(qc.Quota).HumanReadable(),
				datasize.ByteSize(qc.Consumption).HumanReadable())
		}
		return
	}
	fs = append(fs, doOK(okf, re, r)...)
	handleRenew(fs, func() error { return e }, re)
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
	Server   string `json: "server"`
	SessionM string `json: "sessionM"`
	Secret   string `json: "secret"`
}

func login(urls, sm, user, pass string) (e error) {
	m := &cmd{
		Cred:    &credentials{User: user, Pass: pass},
		Manager: sm,
		Cmd:     open,
	}
	var r *h.Response
	fs := []func(){
		func() {
			r, e = postCmd(urls, m)
		},
	}
	fe := func(d error) { e = d }
	okf := func(bs []byte) (d error) {
		li := &loginInfo{
			Server: urls, SessionM: sm, Secret: string(bs),
		}
		d = writeSecret(li)
		return
	}
	fs = append(fs, doOK(okf, fe, r)...)
	trueFF(fs, func() bool { return e == nil })
	return
}

func logout() (e error) {
	m := &cmd{
		Cmd: clöse,
	}
	var r *h.Response
	var li *loginInfo
	fs := []func(){
		func() {
			li, e = readSecret()
		},
		func() {
			m.Secret, m.Manager = li.Secret, li.SessionM
			r, e = postCmd(li.Server, m)
		},
	}
	fe := func(d error) { e = d }
	//only if error is "token exp..."
	okf := func(bs []byte) (d error) {
		d = os.Remove(loginSecretFile)
		return
	}
	fs = append(fs, doOK(okf, fe, r)...)
	handleRenew(fs, func() error { return e }, fe)
	return
}

func handleRenew(fs []func(), re func() error,
	te func(error)) {
	rnw := func() {
		if re() != nil &&
			strings.HasPrefix(re().Error(), "token expired") {
			var li *loginInfo
			var r *h.Response
			fsn := []func(){
				func() {
					var e error
					li, e = readSecret()
					te(e)
				},
				func() {
					m := &cmd{
						Cmd:     renew,
						Manager: li.SessionM,
						Secret:  li.Secret,
					}
					var e error
					r, e = postCmd(li.Server, m)
					te(e)
				},
			}
			okf := func(bs []byte) (d error) {
				li.Secret = string(bs)
				d = writeSecret(li)
				return
			}
			fsn = append(fsn, doOK(okf, te, r)...)
			fsn = append(fsn, fs...)
			trueFF(fsn, func() bool { return re() == nil })
		}
	}
	trueFF(append(fs, rnw), func() bool { return re() == nil })
	return
}

func writeSecret(li *loginInfo) (e error) {
	bs, e := json.Marshal(li)
	if e == nil {
		e = ioutil.WriteFile(loginSecretFile, bs, 0644)
	}
	return
}

func readSecret() (li *loginInfo, e error) {
	bs, e := ioutil.ReadFile(loginSecretFile)
	if e == nil {
		li = new(loginInfo)
		e = json.Unmarshal(bs, li)
	}
	return
}

func postCmd(urls string, c *cmd) (r *h.Response, e error) {
	bs, e := json.Marshal(c)
	if e == nil {
		buff := bytes.NewBuffer(bs)
		u := urls + apiCmd
		r, e = h.Post(u, "text/json", buff)
	}
	return
}

func doOK(ok func([]byte) error, fe func(error),
	r *h.Response) (fs []func()) {
	var bs []byte
	var e error
	fs = []func(){
		func() {
			bs, e = ioutil.ReadAll(r.Body)
			r.Body.Close()
			fe(e)
		},
		func() {
			if r.StatusCode == h.StatusOK {
				e = ok(bs)
			} else {
				e = fmt.Errorf("%s", string(bs))
			}
			fe(e)
		},
	}
	return
}

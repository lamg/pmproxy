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
	"github.com/lamg/pmproxy"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/spf13/afero"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	h "net/http"
	"strings"
)

type PMClient struct {
	Fs      afero.Fs
	PostCmd func(string, *mng.Cmd) (*h.Response, error)
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
		u := urls + pmproxy.ApiCmd
		r, e = h.Post(u, "text/json", buff)
		if e == nil && r.StatusCode == h.StatusBadRequest {
			unmarshalErr(r.Body)
		}
	}
	return
}

func unmarshalErr(rc io.ReadCloser) (e error) {
	bs, e := ioutil.ReadAll(rc)
	if e == nil {
		rc.Close()
		errs := []error{
			new(mng.ManagerErr),
			new(mng.CheckErr),
			new(mng.ForbiddenByRulesErr),
			new(mng.NoConnErr),
			new(mng.NoAdmErr),
			new(mng.QuotaReachedErr),
		}
		ib := func(i int) bool {
			re := json.Unmarshal(bs, errs[i])
			return re == nil
		}
		ok, n := alg.BLnSrch(ib, len(errs))
		if ok {
			e = errs[n]
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

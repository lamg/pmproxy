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
// Public License along with PMProxy. If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	"context"
	"errors"
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/lamg/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"os"
	"path"
	"testing"
	"time"
)

func TestConf(t *testing.T) {
	home, e := os.UserHomeDir()
	require.NoError(t, e)
	fs := afero.NewMemMapFs()
	e = afero.WriteFile(fs, path.Join(home, confDir, confFile),
		[]byte(cfgExample), 0644)
	require.NoError(t, e)
	p, e := load(fs)
	require.NoError(t, e)
	require.NotNil(t, p.Proxy)
	require.NotNil(t, p.Api)
	require.Equal(t, []string{"/dashboard", "/auth/login", "/about"},
		p.Api.ExcludedRoutes)
}

var cfgExample = `
[api]
	excludedRoutes=["/dashboard","/auth/login","/about"]
	httpsCert="cert.pem"
	httpsKey="key.pem"
	webStaticFilesDir="staticFiles"
	persistInterval="5m"
	[api.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":4443"
		fastOrStd=false

[proxy]
	dialTimeout="10s"
	[proxy.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":8081"
		fastOrStd=false

`

func TestConcurrency(t *testing.T) {
	fs := afero.NewMemMapFs()
	cfile, _, e := mng.ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, cfile, []byte(cfg), 0644)
	require.NoError(t, e)
	cmf, dlr, _, e := mng.Load("", fs)
	dlr.Dialer = mng.MockDialerF
	require.NoError(t, e)
	clients := []struct {
		ip   string
		reqs []req
	}{
		{
			ht.DefaultRemoteAddr,
			[]req{
				{
					toProxy: od4,
					okf:     falseRulesEval,
				},
				{
					toApi: &mng.Cmd{
						Manager: "sessions",
						Cmd:     mng.Open,
						Cred:    &mng.Credentials{User: "user0", Pass: "pass0"},
					},
					okf: okCmd,
				},
			},
		},
		{
			"10.0.0.1",
			[]req{
				{
					toApi: &mng.Cmd{
						Manager: "sessions",
						Cmd:     mng.Open,
						Cred: &mng.Credentials{
							User: "user1",
							Pass: "pass1",
						},
					},
					toProxy: od4,
					okf:     okCmdRes,
				},
			},
		},
	}
	rc := make(chan reqBool, len(clients)+1)
	inf := func(i int) {
		go func() {
			inf0 := func(j int) {
				req := clients[i].reqs[j]
				c := req.toApi
				if c != nil {
					c.IP = clients[i].ip
					cmf(c)
				}
				var res error
				if req.toProxy != "" {
					rqp := &proxy.ReqParams{IP: clients[i].ip}
					ctx := context.WithValue(context.Background(),
						proxy.ReqParamsK, rqp)
					_, res = dlr.DialContext(ctx, tcp, od4)
				}
				ok := req.okf(c, res)
				rc <- reqBool{i: i, j: j, ok: ok}
			}
			alg.Forall(inf0, len(clients[i].reqs))
		}()
	}
	alg.Forall(inf, len(clients))
	for k := range rc {
		require.True(t, k.ok, "At i:%d j:%d", k.i, k.j)
		if k.i == len(clients)-1 {
			break
		}
	}
}

const (
	od4 = "1.1.1.1:443"
	tcp = "tcp"
)

type reqBool struct {
	ok   bool
	i, j int
}

type req struct {
	toApi   *mng.Cmd
	toProxy string
	okf     func(*mng.Cmd, error) bool
}

func okCmd(c *mng.Cmd, r error) (ok bool) {
	ok = c.Err == nil
	return
}

func okCmdRes(c *mng.Cmd, r error) (ok bool) {
	ok = c.Err == nil && r == nil
	return
}

func falseRulesEval(c *mng.Cmd, r error) (ok bool) {
	var fr *mng.ForbiddenByRulesErr
	ok = errors.As(r, &fr)
	return
}

const cfg = `
rules = "sessions ∧ down"

[[sessionIPM]]
	name = "sessions"
	auth = "map"

[[dwnConsR]]
	name = "down"
	userDBN = "map"
	resetCycle = "1h"
	[dwnConsR.quotaMap]
		group0 = "1 MB"

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"
		user1 = "pass1"
	[mapDB.userGroup]
		user0 = ["group0"]
`

func TestServe(t *testing.T) {
	// server configuration
	home, e := os.UserHomeDir()
	require.NoError(t, e)
	fs := afero.NewMemMapFs()
	e = afero.WriteFile(fs, path.Join(home, confDir, confFile),
		[]byte(cfgExample), 0644)
	require.NoError(t, e)
	// managers configuration
	cfile, _, e := mng.ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, cfile, []byte(cfg), 0644)
	require.NoError(t, e)

	go Serve(fs)

	cl := &PMClient{Fs: fs, PostCmd: PostCmd}
	var dr *mng.DiscoverRes
	times, lapse := 50, 200*time.Millisecond
	ib := func(i int) (ok bool) {
		time.Sleep(lapse)
		dr, e = cl.discoverC("https://localhost:4443", "")
		ok = e == nil
		return
	}
	ok, _ := alg.BLnSrch(ib, times)
	if ok {
		expected := &mng.DiscoverRes{
			Result: "false",
			MatchMng: map[string]*mng.MatchType{
				"sessions": &mng.MatchType{
					Match: false,
					Type:  mng.SessionIPMK,
				},
			},
		}
		require.Equal(t, expected, dr)
	}
}

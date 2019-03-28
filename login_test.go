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
	pred "github.com/lamg/predicate"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"path"
	"testing"
	"time"
)

type testReq struct {
	command *cmd
	rAddr   string
	code    int
	bodyOK  func([]byte)
}

type testResp struct {
	sessionMng, secr, body string
}

func TestLogin(t *testing.T) {
	ifh := basicConf(t)
	loginIP := "192.168.1.1"
	loginAddr := loginIP + ":1982"
	mapHasUser0 := func(mäp []byte) (ok bool) {
		var ipUsr map[string]string
		e := json.Unmarshal(mäp, &ipUsr)
		ok = e == nil
		if ok {
			u, oku := ipUsr[loginIP]
			ok = oku && u == user0
		}
		return
	}
	u0Cmd := func(p *testResp) testReq {
		return testReq{
			command: &cmd{
				Manager: p.sessionMng,
				Cmd:     get,
				Secret:  p.secr,
			},
			rAddr:  loginAddr,
			code:   h.StatusOK,
			bodyOK: func(bs []byte) { require.True(t, mapHasUser0(bs)) },
		}
	}
	noU0Cmd := func(p *testResp) testReq {
		return testReq{
			command: &cmd{
				Manager: p.sessionMng,
				Cmd:     get,
				Secret:  p.secr,
			},
			rAddr: loginAddr,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				require.False(t, mapHasUser0(bs))
			},
		}
	}
	ts := []func(*testResp) testReq{
		func(p *testResp) testReq { return discoverTR(t, p, loginAddr) },
		func(p *testResp) testReq { return loginTR(t, p, loginAddr, 0) },
		u0Cmd,
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{Manager: p.sessionMng, Secret: p.secr,
					Cmd: clöse},
				rAddr:  loginAddr,
				code:   h.StatusOK,
				bodyOK: func(bs []byte) { require.Equal(t, 0, len(bs)) },
			}
		},
		noU0Cmd,
		func(p *testResp) testReq {
			return loginTR(t, p, loginAddr, 2*time.Second)
		},
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{
					Manager: p.sessionMng,
					Cmd:     get,
					Secret:  p.secr,
				},
				rAddr: loginAddr,
				code:  h.StatusBadRequest,
				bodyOK: func(bs []byte) {
					require.Equal(t, "token is expired by 1s\n", string(bs))
				},
			}
		},
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{Cmd: renew, Manager: p.sessionMng},
				rAddr:   loginAddr,
				code:    h.StatusOK,
				bodyOK: func(bs []byte) {
					p.secr = string(bs)
				},
			}
		},
		u0Cmd,
	}

	runReqTests(t, ts, ifh)
}

func discoverTR(t *testing.T, trp *testResp,
	addr string) (r testReq) {
	r = testReq{
		command: &cmd{
			Cmd:     discover,
			Manager: resourcesK,
		},
		rAddr: addr,
		code:  h.StatusOK,
		bodyOK: func(bs []byte) {
			s := new(spec)
			e := json.Unmarshal(bs, s)
			require.NoError(t, e)
			t.Logf(pred.String(s.Result))
			trp.sessionMng = s.Result.A.String
		},
	}
	return
}

func loginTR(t *testing.T, trp *testResp,
	rAddr string, sleepAft time.Duration) (r testReq) {
	r = testReq{
		command: &cmd{
			Cmd:     open,
			Manager: trp.sessionMng,
			Cred:    &credentials{User: user0, Pass: pass0},
		},
		rAddr: rAddr,
		code:  h.StatusOK,
		bodyOK: func(bs []byte) {
			require.NotEqual(t, 0, len(bs))
			trp.secr = string(bs)
			time.Sleep(sleepAft)
		},
	}
	return
}

func runReqTests(t *testing.T, ts []func(*testResp) testReq,
	hf h.HandlerFunc) {
	trp := new(testResp)
	inf := func(i int) {
		req := ts[i](trp)
		req.command.Secret = trp.secr
		bs, e := json.Marshal(req.command)
		require.NoError(t, e)
		w, r := ht.NewRecorder(),
			ht.NewRequest(h.MethodPost, apiCmd, bytes.NewBuffer(bs))
		r.RemoteAddr = req.rAddr
		hf(w, r)
		require.Equal(t, req.code, w.Code, "At %d: %s", i,
			w.Body.String())
		req.bodyOK(w.Body.Bytes())
	}
	forall(inf, len(ts))
}

func testConf() (fs afero.Fs) {
	conf := `
	admins = "user0"
	rules = "sessions ∧ downloads"
	
	[[userDB]]
		adOrMap = false
		name = "mapDB"
		[userDB.quotaMap]
			group0 = "600MB"
		[userDB.params]
			[userDB.params.groups]
				user0 = ["group0"]
			[userDB.params.userPass]
				user0 = "pass0"
	
	[[sessionIPM]]
		authName = "mapDB"
		name = "sessions"

	[[dwnConsR]]
		name = "downloads"
		userQuota = "mapDB"
		lastReset = "2019-03-04T12:58:32-05:00"
		resetCycle = "24h0m0s"
	`
	fs = afero.NewMemMapFs()
	afero.WriteFile(fs, path.Join(home(), homeConfigDir, configFile),
		[]byte(conf), 0644)
	return
}

func basicConf(t *testing.T) (hnd h.HandlerFunc) {
	c, e := newConf(testConf())
	require.NoError(t, e)
	res := c.res
	res.cr.expiration = time.Second
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	hnd = ifh.serveHTTP
	return
}

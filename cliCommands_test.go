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
	"errors"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
	"time"
)

const (
	user0  = "user0"
	pass0  = "pass0"
	group0 = "group0"
	pmpurl = "https://pmproxy.org"
)

func TestLogin(t *testing.T) {
	fs, ifh, _ := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd(ht.DefaultRemoteAddr, ifh),
	}
	e := cl.login(pmpurl, "", user0, pass0)
	var avm *availableMngErr
	require.True(t, errors.As(e, &avm))
	e = cl.login(pmpurl, avm.mngs[0], user0, pass0)
	require.NoError(t, e)
	ok, e := afero.Exists(fs, loginSecretFile)
	require.True(t, e == nil && ok)
	dr, e := cl.discoverC("", "")
	require.NoError(t, e)
	if testing.Verbose() {
		printDR(dr)
	}
	ui, e := cl.status("", "")
	require.NoError(t, e)
	xui := &mng.UserInfo{
		UserName:    user0,
		Name:        user0,
		Groups:      []string{group0},
		Quota:       "1024 B",
		Consumption: "0 B",
		BytesQuota:  1024,
		BytesCons:   0,
		IsAdmin:     true,
	}
	require.Equal(t, xui, ui)
}

func TestShowMng(t *testing.T) {
	_, cl := loginTest(t)
	dj, e := cl.showMng("down")
	require.NoError(t, e)
	down := new(mng.DwnConsR)
	e = json.Unmarshal([]byte(dj), down)
	require.NoError(t, e)
	exp := &mng.DwnConsR{
		Name:       "down",
		UserDBN:    "map",
		ResetCycle: 168 * time.Hour,
		GroupQuota: map[string]string{
			"group0": "1 KB",
			"group1": "512 B",
		},
	}
	require.Equal(t, exp, down)
}

func TestReset(t *testing.T) {
	_, cl := loginTest(t)
	user1, down := "user1", "down"
	e := cl.reset(down, user1)
	require.NoError(t, e)
	ui, e := cl.status(down, user1)
	require.NoError(t, e)
	rui := &mng.UserInfo{
		Name:        user1,
		UserName:    user1,
		Groups:      []string{"group1"},
		Quota:       "512 B",
		BytesQuota:  512,
		Consumption: "1 B",
		BytesCons:   1,
	}
	require.Equal(t, rui, ui)
}

func loginTest(t *testing.T) (fs afero.Fs, cl *PMClient) {
	fs, ifh, _ := basicConfT(t)
	cl = &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd(ht.DefaultRemoteAddr, ifh),
	}
	cl.login(pmpurl, "sessions", user0, pass0)
	return
}

func basicConfT(t *testing.T) (fs afero.Fs, ifh h.HandlerFunc,
	prs func() error) {
	fl, _, e := mng.ConfPath()
	require.NoError(t, e)
	fs = afero.NewMemMapFs()
	e = afero.WriteFile(fs, fl, []byte(conf0), 0644)
	require.NoError(t, e)
	ch, _, prs, e := mng.Load("", fs)
	require.NoError(t, e)
	ifh = StdIface("", ch, []string{})
	return
}

func testPostCmd(addr string,
	hnd h.HandlerFunc) func(string, *mng.Cmd) (*h.Response, error) {
	return func(u string, m *mng.Cmd) (r *h.Response, e error) {
		rec := ht.NewRecorder()
		bs, e := json.Marshal(m)
		if e == nil {
			q := ht.NewRequest(h.MethodPost,
				"https://pmproxy.org/api/cmd",
				bytes.NewReader(bs))
			q.RemoteAddr = addr + ":1919"
			hnd(rec, q)
			r = rec.Result()
			if e == nil && r.StatusCode == h.StatusBadRequest {
				e = unmarshalErr(r.Body)
			}
		}
		return
	}
}

const conf0 = `
rules = "sessions ∧ down"
admins = ["user0"]

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"
		user1 = "pass1"
	[mapDB.userGroups]
		user0 = ["group0"]
		user1 = ["group1"]

[[sessionIPM]]
	name = "sessions"
	auth = "map"

[[dwnConsR]]
	name = "down"
	userDBN = "map"
	resetCycle = "168h"
	[dwnConsR.groupQuota]
		group0 = "1 KB"
		group1 = "512 B"
`

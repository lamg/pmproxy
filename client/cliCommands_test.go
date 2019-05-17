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

package client

import (
	"bytes"
	"encoding/json"
	alg "github.com/lamg/algorithms"
	pm "github.com/lamg/pmproxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
	"time"
)

func TestLogin(t *testing.T) {
	fs, ifh, _ := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd("127.0.0.1", ifh),
	}
	e := cl.login("", "", pm.User0, pm.Pass0)
	ok, e := afero.Exists(fs, loginSecretFile)
	require.True(t, e == nil && ok)
	dr, e := cl.discoverC("", "")
	require.NoError(t, e)
	if testing.Verbose() {
		printDR(dr)
	}
	ui, e := cl.status("")
	require.NoError(t, e)
	xui := &pm.UserInfo{
		UserName:    pm.User0,
		Name:        pm.User0,
		Groups:      []string{pm.Group0},
		Quota:       "600.0 MB",
		Consumption: "0 B",
		BytesQuota:  629145600,
		BytesCons:   0,
	}
	require.Equal(t, xui, ui)
}

func TestShowMng(t *testing.T) {
	fs, ifh, _ := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd("192.168.1.1", ifh),
	}
	cl.login("", "", pm.User0, pm.Pass0)
	downWeek := "downWeek"
	objT, e := cl.showMng(downWeek)
	require.NoError(t, e)
	require.Equal(t, pm.DwnConsRK, objT.Type)
	kvs := []struct {
		key string
		val interface{}
	}{
		{pm.NameK, downWeek},
		{pm.LastResetK, "2019-04-13T20:00:00-04:00"},
		{pm.ResetCycleK, "168h0m0s"},
		{pm.UserDBK, "mapDB"},
		{
			pm.QuotaMapK,
			map[string]interface{}{
				"group0": "600.0 MB",
				"group1": "1024.0 MB",
			},
		},
	}
	inf := func(i int) {
		require.Equal(t, kvs[i].val, objT.Object[kvs[i].key])
	}
	alg.Forall(inf, len(kvs))
}

func TestShowRules(t *testing.T) {
	fs, ifh, _ := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd("192.168.1.1", ifh),
	}
	cl.login("", "", pm.User0, pm.Pass0)
	s, e := cl.showRules()
	require.NoError(t, e)
	require.Equal(t, "campus ∧ sessions ∧ ((day ∧ downWeek) ∨ "+
		"(night ∧ downNight)) ∧ ((group0M ∧ bandWidth0) ∨ "+
		"(group1M ∧ bandWidth1))", s)
}

func TestConfUpdate(t *testing.T) {
	fs, _, cf := basicConfT(t)
	cf.Update()
	bs, e := afero.ReadFile(fs, pm.ConfPath())
	require.NoError(t, e)
	t.Log(string(bs))
	// FIXME some objects aren't written
}

func basicConfT(t *testing.T) (fs afero.Fs, hnd h.HandlerFunc,
	c *pm.Conf) {
	pth := pm.ConfPath()
	fs = afero.NewMemMapFs()
	pm.BasicConf(pth, fs)
	ok, e := afero.Exists(fs, pth)
	require.True(t, ok && e == nil)
	nt, e := time.Parse(time.RFC3339, "2019-03-04T19:00:00-05:00")
	require.NoError(t, e)
	c, e = pm.NewConf(fs, func() time.Time { return nt })
	require.NoError(t, e)
	_, ifh, e := pm.NewHnds(c)
	require.NoError(t, e)
	hnd = ifh.ServeHTTP
	return
}

func testPostCmd(addr string,
	hnd h.HandlerFunc) func(string, *pm.Cmd) (*h.Response, error) {
	return func(u string, m *pm.Cmd) (r *h.Response, e error) {
		rec := ht.NewRecorder()
		bs, e := json.Marshal(m)
		if e == nil {
			q := ht.NewRequest(h.MethodPost,
				"https://pmproxy.org/api/cmd",
				bytes.NewReader(bs))
			q.RemoteAddr = addr + ":1919"
			hnd(rec, q)
			r = rec.Result()
		}
		return
	}
	// TODO
}

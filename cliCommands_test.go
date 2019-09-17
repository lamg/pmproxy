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
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
)

const (
	user0  = "user0"
	pass0  = "pass0"
	group0 = "group0"
)

func TestLogin(t *testing.T) {
	fs, ifh, _ := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd("127.0.0.1", ifh),
	}

	e := cl.login("", "", user0, pass0)
	require.NoError(t, e)
	ok, e := afero.Exists(fs, loginSecretFile)
	require.True(t, e == nil && ok)
	dr, e := cl.discoverC("", "")
	require.NoError(t, e)
	if testing.Verbose() {
		printDR(dr)
	}
	ui, e := cl.status("")
	require.NoError(t, e)
	xui := &mng.UserInfo{
		UserName:    user0,
		Name:        user0,
		Groups:      []string{group0},
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
	cl.login("", "", user0, pass0)
	downWeek := "downWeek"
	objT, e := cl.showMng(downWeek)
	require.NoError(t, e)
	require.Equal(t, mng.DwnConsRK, objT.Type)
	kvs := []struct {
		key string
		val interface{}
	}{
		{mng.NameK, downWeek},
		{mng.LastResetK, "2019-04-13T20:00:00-04:00"},
		{mng.ResetCycleK, "168h0m0s"},
		{mng.UserDBK, "mapDB"},
		{
			mng.QuotaMapK,
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

func TestConfUpdate(t *testing.T) {
	fs, _, prs := basicConfT(t)
	e := prs()
	require.NoError(t, e)
	_, fl := mng.ConfPath("")
	bs, e := afero.ReadFile(fs, fl)
	require.NoError(t, e)
	t.Log(string(bs))
	// FIXME some objects aren't written
}

func basicConfT(t *testing.T) (fs afero.Fs, ifh h.HandlerFunc,
	prs func() error) {
	_, fl := mng.ConfPath("")
	fs = afero.NewMemMapFs()
	mng.BasicConf(fl, fs)
	ok, e := afero.Exists(fs, fl)
	require.True(t, ok && e == nil)
	ch, _, prs, e := mng.Load("", fs)
	require.NoError(t, e)
	ifh = stdIface("", ch)
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
		}
		return
	}
	// TODO
}
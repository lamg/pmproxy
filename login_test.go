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
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
	"time"
)

func TestLogin(t *testing.T) {
	fs, ifh := basicConfT(t)
	cl := &PMClient{
		Fs:      fs,
		PostCmd: testPostCmd("192.168.1.1", ifh),
	}
	e := cl.login("", "", user0, pass0)
	ok, e := afero.Exists(fs, loginSecretFile)
	require.True(t, e == nil && ok)
	bs, e := afero.ReadFile(fs, loginSecretFile)
	t.Log(string(bs))
	require.NoError(t, e)
	ui, e := cl.status("")
	require.NoError(t, e)
	xui := &userInfo{
		UserName:    user0,
		Name:        user0,
		Groups:      []string{group0},
		Quota:       "600 MB",
		Consumption: "0 B",
	}
	require.Equal(t, ui, xui)
}

func basicConfT(t *testing.T) (fs afero.Fs, hnd h.HandlerFunc) {
	pth := confPath()
	fs = afero.NewMemMapFs()
	basicConf(pth, fs)
	ok, e := afero.Exists(fs, pth)
	require.True(t, ok && e == nil)
	c, e := newConf(fs)
	require.NoError(t, e)
	res := c.res
	res.cr.expiration = time.Second
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	hnd = ifh.serveHTTP
	return
}

func testPostCmd(addr string,
	hnd h.HandlerFunc) func(string, *cmd) (*h.Response, error) {
	return func(u string, m *cmd) (r *h.Response, e error) {
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

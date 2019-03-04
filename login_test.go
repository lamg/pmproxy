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
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
)

type testReq struct {
	obj    interface{}
	rAddr  string
	meth   string
	path   string
	code   int
	bodyOK func([]byte)
}

func TestLogin(t *testing.T) {
	c, e := newConfWith(func() (e error) { return })
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	loginIP := "192.168.1.1"
	loginAddr := loginIP + ":1982"
	mapHasUser0 := func(bs []byte) (ok bool) {
		var ui map[string]string
		e := json.Unmarshal(bs, &ui)
		ok = e == nil
		if ok {
			u, oku := ui[loginIP]
			ok = oku && u == user0
		}
		return
	}
	u0Cmd := testReq{
		obj:    &cmd{Manager: defaultSessionIPM, Cmd: get},
		meth:   h.MethodPost,
		rAddr:  loginAddr,
		path:   apiCmd,
		code:   h.StatusOK,
		bodyOK: func(bs []byte) { require.True(t, mapHasUser0(bs)) },
	}
	noU0Cmd := u0Cmd
	noU0Cmd.bodyOK = func(bs []byte) {
		require.False(t, mapHasUser0(bs))
	}
	var secr string
	ts := []testReq{
		loginTR(t, func(s string) { secr = s }, loginAddr),
		u0Cmd,
		{
			obj:    "",
			meth:   h.MethodDelete,
			rAddr:  loginAddr,
			path:   apiAuth,
			code:   h.StatusOK,
			bodyOK: func(bs []byte) { require.Equal(t, 0, len(bs)) },
		},
		noU0Cmd,
	}
	runReqTests(t, ts, ifh.serveHTTP, func() string { return secr })
}

func loginTR(t *testing.T, body func(string),
	rAddr string) (r testReq) {
	r = testReq{
		obj:   &credentials{User: user0, Pass: pass0},
		meth:  h.MethodPost,
		rAddr: rAddr,
		path:  apiAuth,
		code:  h.StatusOK,
		bodyOK: func(bs []byte) {
			require.NotEqual(t, 0, len(bs))
			body(string(bs))
		},
	}
	return
}

func runReqTests(t *testing.T, ts []testReq, hf h.HandlerFunc,
	secr func() string) {
	inf := func(i int) {
		bs, e := json.Marshal(ts[i].obj)
		require.NoError(t, e)
		w, r := ht.NewRecorder(),
			ht.NewRequest(ts[i].meth, ts[i].path, bytes.NewBuffer(bs))
		r.Header.Set(authHd, secr())
		r.RemoteAddr = ts[i].rAddr
		hf(w, r)
		require.Equal(t, ts[i].code, w.Code, "At %d: %s", i,
			w.Body.String())
		ts[i].bodyOK(w.Body.Bytes())
	}
	forall(inf, len(ts))
}

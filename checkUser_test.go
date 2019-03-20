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
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestCheckUser(t *testing.T) {
	c, e := newConfWith(initSessionRules)
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	loginAddr := "10.3.10.3:1984"
	nLoggedIn := "10.2.1.1"
	var secr, sessionMng string
	trp := new(testResp)
	ts := []testReq{
		discoverTR(t, trp, loginAddr),
		loginTR(t, trp, loginAddr, 0),
		{
			command: &cmd{Manager: sessionMng, Cmd: check,
				Secret: secr},
			rAddr: loginAddr,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				require.Equal(t, 0, len(bs), "Body: %s", string(bs))
			},
		},
		{
			command: &cmd{Manager: sessionMng, Cmd: check,
				Secret: secr},
			rAddr: nLoggedIn + ":1919",
			code:  h.StatusBadRequest,
			bodyOK: func(bs []byte) {
				withoutNewLine := string(bs[:len(bs)-1])
				require.Equal(t, userNotLoggedAt(user0, nLoggedIn).Error(),
					withoutNewLine)
			},
		},
	}
	runReqTests(t, ts, ifh.serveHTTP, secr)
}

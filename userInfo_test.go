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
	"encoding/json"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestUserInfo(t *testing.T) {
	c, e := newConfWith(initDefaultDwnConsR)
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	loginAddr := "192.12.12.3:1919"
	trp := new(testResp)
	ts := []func(p *testResp) testReq{
		func(p *testResp) testReq { return discoverTR(t, p, loginAddr) },
		func(p *testResp) testReq { return loginTR(t, p, loginAddr, 0) },
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{
					Manager: defaultUserDB,
					Cmd:     get,
					Secret:  trp.secr,
				},
				rAddr: loginAddr,
				code:  h.StatusOK,
				bodyOK: func(bs []byte) {
					info := new(userInfo)
					e := json.Unmarshal(bs, info)
					require.NoError(t, e)
					require.Equal(t, user0, info.UserName)
					require.Equal(t, user0, info.Name)
					require.Equal(t, "600.0 MB", info.Quota)
				},
			}
		},
	}
	runReqTests(t, ts, ifh.serveHTTP)
}

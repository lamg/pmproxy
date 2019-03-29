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
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestUserStatus(t *testing.T) {
	ifh := basicConfT(t)
	loginAddr := "192.168.1.1:1982"
	ts := []func(p *testResp) testReq{
		func(p *testResp) testReq { return discoverTR(t, p, loginAddr) },
		func(p *testResp) testReq { return loginTR(t, p, loginAddr, 0) },
		func(p *testResp) testReq { return checkConsTR(t, loginAddr, 0) },
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{
					Manager: defaultDwnConsR,
					Cmd:     set,
					String:  user0,
					Uint64:  1024,
				},
				rAddr: loginAddr,
				code:  h.StatusOK,
				bodyOK: func(bs []byte) {
					require.Equal(t, 0, len(bs), "Body: %s", string(bs))
				},
			}
		},
		func(p *testResp) testReq {
			return checkConsTR(t, loginAddr, 1024)
		},
	}
	runReqTests(t, ts, ifh)
}

func checkConsTR(t *testing.T, loginAddr string,
	cons uint64) (tr testReq) {
	bsz := new(datasize.ByteSize)
	e := bsz.UnmarshalText([]byte(defaultQuota))
	require.NoError(t, e)
	defQt := bsz.Bytes()
	tr = testReq{
		command: &cmd{
			Cmd:     get,
			Manager: defaultDwnConsR,
		},
		rAddr: loginAddr,
		code:  h.StatusOK,
		bodyOK: func(bs []byte) {
			qc := new(qtCs)
			e := json.Unmarshal(bs, qc)
			require.NoError(t, e)
			require.Equal(t, defQt, qc.Quota)
			require.Equal(t, cons, qc.Consumption)
		},
	}
	return
}

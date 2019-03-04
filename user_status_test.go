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

type qtCs struct {
	Quota uint64 `json: "quota"`
	Cons  uint64 `json: "consumption"`
}

func TestUserStatus(t *testing.T) {
	c, e := newConfWith(func() (e error) { return })
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	var secr string
	bsz := new(datasize.ByteSize)
	e = bsz.UnmarshalText([]byte(defaultQuota))
	require.NoError(t, e)
	defQt := bsz.Bytes()
	loginAddr := "192.168.1.1:1982"
	ts := []testReq{
		loginTR(t, func(s string) { secr = s }, loginAddr),
		{
			obj:   "",
			meth:  h.MethodGet,
			path:  apiUserStatus,
			rAddr: loginAddr,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				qc := new(qtCs)
				e := json.Unmarshal(bs, qc)
				require.NoError(t, e)
				require.Equal(t, defQt, qc.Quota)
				require.Equal(t, uint64(0), qc.Cons)
			},
		},
	}
	runReqTests(t, ts, ifh.serveHTTP, func() string { return secr })
}

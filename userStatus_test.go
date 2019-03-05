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
	"github.com/lamg/viper"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
	"time"
)

func TestUserStatus(t *testing.T) {
	c, e := newConfWith(initDefaultDwnConsR)
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	var secr string
	loginAddr := "192.168.1.1:1982"
	ts := []testReq{
		loginTR(t, func(s string) { secr = s }, loginAddr),
		checkConsTR(t, loginAddr, 0),
		{
			obj: &struct {
				Name  string `json: "name"`
				Value uint64 `json: "value"`
			}{
				Name:  user0,
				Value: 1024,
			},
			meth:  h.MethodPut,
			path:  apiUserStatus,
			rAddr: loginAddr,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				require.Equal(t, 0, len(bs), "Body: %s", string(bs))
			},
		},
		checkConsTR(t, loginAddr, 1024),
	}
	runReqTests(t, ts, ifh.serveHTTP, func() string { return secr })
}

func checkConsTR(t *testing.T, loginAddr string,
	cons uint64) (tr testReq) {
	bsz := new(datasize.ByteSize)
	e := bsz.UnmarshalText([]byte(defaultQuota))
	require.NoError(t, e)
	defQt := bsz.Bytes()
	tr = testReq{
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
			require.Equal(t, cons, qc.Consumption)
		},
	}
	return
}

func initDefaultDwnConsR() (e error) {
	initDefaultSessionIPM()
	viper.SetDefault(ipQuotaK, []map[string]interface{}{
		{
			nameK:       defaultIPQuota,
			userGroupNK: defaultUserDB,
			quotaMapK: map[string]string{
				group0: defaultQuota,
			},
		},
	})
	viper.SetDefault(dwnConsRK, []map[string]interface{}{
		{
			nameK:       defaultDwnConsR,
			ipQuotaK:    defaultIPQuota,
			lastResetK:  time.Now().Format(time.RFC3339),
			resetCycleK: time.Duration(24 * time.Hour).String(),
		},
	})
	return
}

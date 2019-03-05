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
	var secr string
	ts := []testReq{
		loginTR(t, func(s string) { secr = s }, loginAddr),
		{
			obj:   "",
			meth:  h.MethodGet,
			rAddr: loginAddr,
			path:  apiUserInfo,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				info := new(cmdInfo)
				e := json.Unmarshal(bs, info)
				require.NoError(t, e)
				require.Equal(t, user0, info.UserName)
				require.Equal(t, user0, info.Name)
				require.True(t, info.IsAdmin)
				require.Equal(t, uint64(629145600), info.QuotaGroup)
			},
		},
	}
	runReqTests(t, ts, ifh.serveHTTP, func() string { return secr })
}

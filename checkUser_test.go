package pmproxy

import (
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestCheckUser(t *testing.T) {
	c, e := newConfWith(initDefaultSessionIPM)
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	loginAddr := "10.3.10.3:1984"
	nLoggedIn := "10.2.1.1"
	var secr string
	ts := []testReq{
		loginTR(t, func(s string) { secr = s }, loginAddr),
		{
			obj:   "",
			meth:  h.MethodGet,
			rAddr: loginAddr,
			path:  apiCheckUser,
			code:  h.StatusOK,
			bodyOK: func(bs []byte) {
				require.Equal(t, 0, len(bs), "Body: %s", string(bs))
			},
		},
		{
			obj:   "",
			meth:  h.MethodGet,
			rAddr: nLoggedIn + ":1919",
			path:  apiCheckUser,
			code:  h.StatusBadRequest,
			bodyOK: func(bs []byte) {
				withoutNewLine := string(bs[:len(bs)-1])
				require.Equal(t, userNotLoggedAt(user0, nLoggedIn).Error(),
					withoutNewLine)
			},
		},
	}
	runReqTests(t, ts, ifh.serveHTTP, func() string { return secr })
}
